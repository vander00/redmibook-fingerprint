#include "tls_key.hpp"
/*
Copyright (C) 2022  pom@vro.life

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include <netinet/in.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>

#include <cstring>
#include <cstdio>
#include <ios>
#include <memory>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>
#include <list>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <functional>
#include <unordered_map>

#include <libusb-1.0/libusb.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#include <jinx/async.hpp>
#include <jinx/logging.hpp>
#include <jinx/macros.hpp>
#include <jinx/queue.hpp>
#include <jinx/raii.hpp>
#include <jinx/usb/usb.hpp>

#include "async.hpp"
#include "crypto.hpp"
#include "fpcbio.hpp"
#include "fpc9201.hpp"
#include "manager.hpp"
#include "fingerprint.hpp"
#include "protocol.hpp"
#include "usb_transfer.hpp"

#define CTRL_HOST_TO_DEVICE 0x40
#define CTRL_DEVICE_TO_HOST 0xC0
#define SENSOR_WIDTH 112
#define SENSOR_HEIGHT 88

namespace  fpc9201 {

using namespace jinx;
using namespace jinx::usb;
using namespace jinx::dbus;
using namespace jinx::openssl;
using namespace fpcbio;
using namespace fpc;

JINX_RAII_SIMPLE_OBJECT(HeapBuffer, unsigned char, ::free); // NOLINT

typedef std::shared_ptr<BIOPipe> BIOPipePtr;

struct FPCEvent
{
    enum {
        Initial,
        TLS_Ready,
        FPC_Event,
        FPP_StartSensor,
        FPP_StopSensor,
        FPP_FingerDown,
        FPP_Image,
        FPP_EnrollVerifyStop,
        FPP_TransportFailed,
        FPP_Suspend,
        FPP_Resume
    } _type;
    struct fpc_event _ev;
    std::vector<FPCBuffer> _buffers{};
    error::Error _error{};
    uint64_t _generation{};
};

static FPCEvent frame_event(fpc::WireEvent&& frame,BIOPipePtr& pipe) {
    FPCEvent event{FPCEvent::FPC_Event,{frame.code,frame.length,frame.result},{}};
    size_t offset=0;
    while(offset<frame.body.size()){
        auto buffer=pipe->_allocator.allocate(FPCBufferConfig{});if(!buffer)throw std::bad_alloc();
        auto view=buffer->slice_for_producer();size_t size=std::min(view.size(),frame.body.size()-offset);
        memcpy(view.data(),frame.body.data()+offset,size);buffer->commit(size).abort_on(Failed_,"buffer overflow");
        event._buffers.push_back(std::move(buffer));offset+=size;
    }
    return event;
}

static void start(fingerpp::Manager* manager, fingerpp::USBDeviceInfo* info, USBDeviceHandle&& handle);

struct DeviceState
{
    bool _finger_present{};
    bool _finger_needed{};
    DBusConnection* _connection{};
    std::string _path;
    void set(bool present,bool needed){
        if(present==_finger_present && needed==_finger_needed)return;
        _finger_present=present;_finger_needed=needed;
        if(!_connection || _path.empty())return;
        AsyncDBusMessage signal{dbus_message_new_signal(_path.c_str(),"org.freedesktop.DBus.Properties","PropertiesChanged")};
        if(!signal)return;
        DBusMessageIter args{},changed{},invalidated{};dbus_message_iter_init_append(signal,&args);
        const char* interface="net.reactivated.Fprint.Device";dbus_message_iter_append_basic(&args,DBUS_TYPE_STRING,&interface);
        dbus_message_iter_open_container(&args,DBUS_TYPE_ARRAY,"{sv}",&changed);
        const char* names[2]={"finger-present","finger-needed"};dbus_bool_t values[2]={dbus_bool_t(present),dbus_bool_t(needed)};
        for(unsigned i=0;i<2;++i){DBusMessageIter entry{},variant{};dbus_message_iter_open_container(&changed,DBUS_TYPE_DICT_ENTRY,nullptr,&entry);
            dbus_message_iter_append_basic(&entry,DBUS_TYPE_STRING,&names[i]);dbus_message_iter_open_container(&entry,DBUS_TYPE_VARIANT,"b",&variant);
            dbus_message_iter_append_basic(&variant,DBUS_TYPE_BOOLEAN,&values[i]);dbus_message_iter_close_container(&entry,&variant);dbus_message_iter_close_container(&changed,&entry);}
        dbus_message_iter_close_container(&args,&changed);dbus_message_iter_open_container(&args,DBUS_TYPE_ARRAY,"s",&invalidated);dbus_message_iter_close_container(&args,&invalidated);
        dbus_connection_send(_connection,signal,nullptr);
    }
};

// class WorkerUI : public DBusObject
// {
// public:
//     WorkerUI() = default;

//     auto& operator() ()
//     {
//         add_node("/EnrollVerify", [&](DBusNode& node){
//             node.add_interface("life.vro.EnrollVerify", [&](DBusInterface& iface){
//                 iface.add_property("fingerprint", "s", "read");
//                 iface.add_property("fingerprint", "s", "read");
//             });
//         });
//         return *this;
//     }
// };

class WorkerEnrollVerify : public AsyncRoutine {
    fingerpp::Manager* _manager{};
    DeviceState* _device_state{};
    Queue<std::queue<FPCEvent>>* _event_queue{};
    Queue<std::queue<FPCEvent>>* _image_queue{};

    Fingerprint _fingerprint{};
    std::unique_ptr<fpc_native_enrollment, decltype(&fpc_native_enrollment_destroy)> _enrollment{nullptr,fpc_native_enrollment_destroy};
    uint64_t _generation{};
    std::string _dbus_path{};

    FingerprintStorage* _storage{};

    bool _verify{};
    int _stage{};

    Queue<std::queue<FPCEvent>>::Put _put_event{};
    Queue<std::queue<FPCEvent>>::Get _get_image{};

    AsyncDBusSend _send_signal{};

public:
    WorkerEnrollVerify& operator ()(
        fingerpp::Manager* manager,
        DeviceState* device_state,
        Queue<std::queue<FPCEvent>>* event_queue,
        Queue<std::queue<FPCEvent>>* image_queue,
        const std::string& user,
        const std::string& name,
        const std::string& dbus_path,
        FingerprintStorage* storage,
        bool verify
    ) {
        _manager = manager;
        _device_state = device_state;
        _event_queue = event_queue;
        _image_queue = image_queue;
        _fingerprint._user = user;
        _fingerprint._name = name;
        _enrollment.reset();
        _dbus_path = dbus_path;
        _storage = storage;

        _verify = verify;
        _stage = 0;
        _generation = ++_storage->capture_generation;
        _storage->operation_active=true;
        if (!_verify) _enrollment.reset(fpc_native_enrollment_create());

        syslog(LOG_AUTH | LOG_INFO, "%s start: %s/%s", _verify ? "verify" : "enroll", user.c_str(), name.c_str());

        async_start(&WorkerEnrollVerify::enroll);
        return *this;
    }

protected:
    void async_finalize() noexcept override {
        _get_image.reset();
        _put_event.reset();
        _fingerprint._name.clear();
        _enrollment.reset();
        if(_storage && _generation==_storage->capture_generation)++_storage->capture_generation;
        if(_storage)_storage->operation_active=false;
        if(_device_state)_device_state->set(false,false);
        AsyncRoutine::async_finalize();
    }

    Async handle_error(const error::Error& error) override {
        auto state = AsyncRoutine::handle_error(error);
        if (state == ControlState::Raise) {
            if (error.category() == category_awaitable()) {
                switch(error.as<ErrorAwaitable>()) {
                    case jinx::ErrorAwaitable::Cancelled:
                        return async_return();
                    default:
                        break;
                }
            }
        }
        return state;
    }

    Async enroll() {
        _device_state->set(false,true);
        _image_queue->reset();
        return *this / _put_event(_event_queue, FPCEvent{FPCEvent::FPP_StartSensor, {}, {}}) / &WorkerEnrollVerify::wait_image;
    }

    Async wait_image() {
        return *this / _get_image(_image_queue) / &WorkerEnrollVerify::parse_image;
    }

    Async parse_image() { // NOLINT
        auto& event = _get_image.get_result();
        if((event._type==FPCEvent::FPP_Image || event._type==FPCEvent::FPP_FingerDown) && event._generation!=_generation)return wait_image();
        if (event._type == FPCEvent::FPP_FingerDown) {
            _device_state->set(true,true);
            
        } else if (event._type == FPCEvent::FPP_Image) {
            // The image has been captured, so the finger is no longer being
            // read. The hardware gives us no FingerUp event, so _finger_present
            // would otherwise latch true forever after the first press and the
            // D-Bus property would always report a finger on the sensor.
            _device_state->set(false,true);
            if (event._generation != _generation) return wait_image();
            std::vector<unsigned char> payload;
            for (auto& buf : event._buffers) {
                auto bytes=buf->slice_for_consumer();
                if(bytes.size()>12+2*FPC_PIXELS-payload.size())
                    return send_signal(_verify?"verify-unknown-error":"enroll-unknown-error",TRUE);
                const auto* data=static_cast<const unsigned char*>(bytes.data());
                payload.insert(payload.end(),data,data+bytes.size());
            }
            if(payload.size()!=12+FPC_PIXELS && payload.size()!=12+2*FPC_PIXELS) {
                jinx_log_error()<<"invalid capture bytes="<<payload.size()<<std::endl;
                return send_signal(_verify?"verify-unknown-error":"enroll-unknown-error",TRUE);
            }
            // Windows ignores the three diagnostic words. The prefix changes
            // across reader sessions; it is not a fixed profile identifier.
            auto metadata=fpc::capture_header(payload.data(),payload.size());
            (void)metadata;
            try {
                const uint8_t* frames[2]={payload.data()+12,payload.data()+12};
                if(payload.size()==12+2*FPC_PIXELS)frames[1]+=FPC_PIXELS;
                unsigned order[5];if(fpc_profile300_rank_frames(frames,2,order)){
                    jinx_log_error()<<"native frame ranking failed"<<std::endl;
                    return send_signal(_verify?"verify-unknown-error":"enroll-unknown-error",TRUE);
                }
                fpc_prepared_capture prepared{};
                int preparation_status=fpc_profile300_prepare(frames[order[0]],FPC_PIXELS,_storage->dead_pixels.data(),
                    _storage->dead_pixels.size(),&prepared);
                if(preparation_status){
                    jinx_log_error()<<"native preparation status="<<preparation_status<<" defects="<<_storage->dead_pixels.size()<<std::endl;
                    return send_signal(_verify?"verify-unknown-error":"enroll-unknown-error",TRUE);
                }
                if(_verify) {
                    bool match=_storage->verify(_fingerprint._user,_fingerprint._name,prepared);
                    return send_signal(match?"verify-match":"verify-retry-scan",match?TRUE:FALSE);
                }
                if(!_enrollment)return send_signal("enroll-unknown-error",TRUE);
                fpc_native_enrollment_report report{};
                int status=fpc_native_enrollment_add(_enrollment.get(),&prepared,&report);
                if(status==112)return send_signal("enroll-failed",TRUE);
                if(status){jinx_log_error()<<"native enrollment status="<<status<<std::endl;return send_signal("enroll-unknown-error",TRUE);}
                if(report.rejection_flags)return send_signal("enroll-remove-and-retry",FALSE);
                _stage=static_cast<int>(report.accepted);
                if(!report.progress.complete)return send_signal("enroll-stage-passed",FALSE);
                fpc_loaded_template completed{};
                if(fpc_native_enrollment_finish(_enrollment.get(),&completed))
                    return send_signal("enroll-unknown-error",TRUE);
                try {_fingerprint._native=serialize_native_template(completed);}
                catch(...){fpc_loaded_template_destroy(&completed);throw;}
                fpc_loaded_template_destroy(&completed);
                if(!_storage->insert_or_update(std::move(_fingerprint)))return send_signal("enroll-failed",TRUE);
                return send_signal("enroll-completed",TRUE);
            }catch(const std::exception& error){
                jinx_log_error()<<"native scan failed: "<<error.what()<<std::endl;
                return send_signal(_verify?"verify-unknown-error":"enroll-unknown-error",TRUE);
            }

        } else if (event._type == FPCEvent::FPP_EnrollVerifyStop) {
            ++_storage->capture_generation;_device_state->set(false,false);
            return *this / _put_event(_event_queue, FPCEvent{FPCEvent::FPP_StopSensor, {}, {}}) / &WorkerEnrollVerify::async_return;
        } else if (event._type == FPCEvent::FPP_TransportFailed) {
            // A suspended USB device invalidates the active scan. Complete
            // the D-Bus operation before the controller tears the session
            // down, otherwise PAM clients keep waiting on a scan that can
            // never produce another image.
            return send_signal(
                _verify ? "verify-unknown-error" : "enroll-unknown-error",
                TRUE);
        }
        return wait_image();
    }

    Async send_signal(const char* status, dbus_bool_t async_return) {
        syslog(LOG_INFO,"native operation result: %s terminal=%u",status,async_return);
        AsyncDBusMessage signal{
            dbus_message_new_signal(_dbus_path.c_str(), "net.reactivated.Fprint.Device", _verify ? "VerifyStatus" : "EnrollStatus")
        };
        DBusMessageIter iter{};
        dbus_message_iter_init_append(signal, &iter);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &status);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &async_return);
        return *this 
            / _send_signal(_manager->get_dbus().get_connection(), signal) 
            / ( async_return == TRUE ? &WorkerEnrollVerify::stop : &WorkerEnrollVerify::next_capture);
    }

    Async next_capture(){
        _generation=++_storage->capture_generation;
        return *this / _put_event(_event_queue,FPCEvent{FPCEvent::FPP_StartSensor,{},{}}) / &WorkerEnrollVerify::wait_image;
    }

    Async stop() {
        ++_storage->capture_generation;
        _device_state->set(false,false);
        return *this / _put_event(_event_queue, FPCEvent{FPCEvent::FPP_StopSensor, {}, {}}) / &WorkerEnrollVerify::async_return;
    }
};

struct MessageData {
    std::string _username{};

    static void release(void* data) {
        delete reinterpret_cast<MessageData*>(data);
    }

    static dbus_int32_t get_slot() {
        static dbus_int32_t slot = -1;
        if (slot == -1) {
            auto ret = dbus_message_allocate_data_slot(&slot);
            if (ret == FALSE) {
                jinx_log_error() << "out of memory\n";
                abort();
            }
        }
        return slot;
    }

    static MessageData* get_data(DBusMessage* msg) {
        auto* data = dbus_message_get_data(msg, get_slot());
        return reinterpret_cast<MessageData*>(data);
    }
};

class WorkerListen : public AsyncRoutine, private jinx::Queue2<std::queue<AsyncDBusMessage>>::CallbackPut {
    typedef jinx::Queue2<std::queue<AsyncDBusMessage>> QueueType;

    AsyncDBusConnection _connection{};
    QueueType* _message_queue{};

    std::string _rule{};
    bool _installed{};

    AsyncDBusMessage _pending_message{};

    AsyncDBusSendWithReply _send_message{};

public:
    WorkerListen& operator ()(
        AsyncDBusConnection& conn,
        QueueType* queue,
        const std::string& rule
    ) {
        _connection = conn;
        _message_queue = queue;
        _rule = rule;

        async_start(&WorkerListen::add_match);
        return *this;
    }
    
    Async handle_error(const error::Error& error) override {
        return async_return();
    }
    
    void async_finalize() noexcept override {
        dbus_connection_remove_filter(_connection,filter_signal,this);
        if(_installed){
            AsyncDBusMessage remove{dbus_message_new_method_call("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","RemoveMatch")};
            if(remove){DBusMessageIter args{};dbus_message_iter_init_append(remove,&args);const char* rule=_rule.c_str();dbus_message_iter_append_basic(&args,DBUS_TYPE_STRING,&rule);dbus_connection_send(_connection,remove,nullptr);}
            _installed=false;
        }
        AsyncRoutine::async_finalize();
    }

    Async add_match() {
        AsyncDBusMessage msg{
            dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch")
        };
        DBusMessageIter args{};
        dbus_message_iter_init_append(msg, &args);
        const char* string = _rule.c_str();
        dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &string);
        return *this / _send_message(_connection, msg, std::chrono::seconds(30)) / &WorkerListen::post;
    }

    Async post() {
        auto& reply = _send_message.get_result();
        if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
            jinx_log_error() << "AddWatch(" << _rule << ") failed: " << dbus_message_get_error_name(reply) << std::endl;
            return async_throw(ErrorAsyncDBus::failed);
        }
        _installed=true;
        dbus_connection_add_filter(_connection, filter_signal, this, nullptr);
        async_start(&WorkerListen::exit);
        return this->async_suspend();
    }

    Async exit() {
        _installed=false;
        AsyncDBusMessage msg{
            dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RemoveMatch")
        };
        DBusMessageIter args{};
        dbus_message_iter_init_append(msg, &args);
        const char* string = _rule.c_str();
        dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &string);
        return *this / _send_message(_connection, msg, std::chrono::seconds(30)) / &WorkerListen::async_return;
    }

    AsyncDBusMessage queue2_put() override {
        return std::move(_pending_message);
    }

    void queue2_cancel_pending_put() override {
        this->async_resume(make_error(ErrorAwaitable::Cancelled)) >> JINX_IGNORE_RESULT;
    }

    static DBusHandlerResult filter_signal(DBusConnection* conn, DBusMessage* msg, void* data) {
        if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL) {
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        auto* self = reinterpret_cast<WorkerListen*>(data);
        auto field=[&](const char* key){std::string prefix=std::string(key)+"='";auto begin=self->_rule.find(prefix);
            if(begin==std::string::npos)return std::string{};begin+=prefix.size();auto end=self->_rule.find("'",begin);return self->_rule.substr(begin,end-begin);};
        auto interface=field("interface"),member=field("member"),sender=field("sender"),path=field("path"),arg0=field("arg0");
        if((!interface.empty() && !dbus_message_has_interface(msg,interface.c_str())) ||
           (!member.empty() && !dbus_message_has_member(msg,member.c_str())) ||
           (!path.empty() && !dbus_message_has_path(msg,path.c_str())))return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        if(!arg0.empty()){DBusMessageIter args{};const char* value=nullptr;
            if(!dbus_message_iter_init(msg,&args) || dbus_message_iter_get_arg_type(&args)!=DBUS_TYPE_STRING)return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
            dbus_message_iter_get_basic(&args,&value);if(!value || arg0!=value)return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;}

        
        self->_pending_message.reset(msg);
        self->_pending_message.ref();
        if (self->_message_queue->put(self).is_not(Queue2Status::Error)) {
            return DBUS_HANDLER_RESULT_HANDLED;
        }
        self->_pending_message.reset();
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
};

// Kept alive while the USB session is torn down, so resume is still observable.
class WorkerPower : public AsyncDBusObject {
    TaskPtr _listener;
    Queue<std::queue<FPCEvent>>* _events{};
    FingerprintStorage* _storage{};
    Queue<std::queue<FPCEvent>>::Put _put{};
public:
    WorkerPower& operator()(Loop* loop,AsyncDBusConnection& connection,Queue<std::queue<FPCEvent>>* events,FingerprintStorage* storage){
        _events=events;_storage=storage;
        add_node("/net/reactivated/Fprint/Power", [](AsyncDBusNode&) {});
        add_method("org.freedesktop.login1.Manager","PrepareForSleep","b",&WorkerPower::power_changed);
        AsyncDBusObject::operator()(connection);
        _listener=loop->task_new<WorkerListen>(connection,get_message_queue(),
            "type='signal',sender='org.freedesktop.login1',path='/org/freedesktop/login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'");
        return *this;
    }
protected:
    void async_finalize() noexcept override {
        if(_listener){async_cancel(_listener)>>JINX_IGNORE_RESULT;_listener.reset();}
        _put.reset();AsyncDBusObject::async_finalize();
    }
    Async power_changed(){
        DBusMessageIter args{};dbus_bool_t sleeping=FALSE;
        if(!dbus_message_iter_init(get_message(),&args) || dbus_message_iter_get_arg_type(&args)!=DBUS_TYPE_BOOLEAN)return run();
        dbus_message_iter_get_basic(&args,&sleeping);_storage->sleeping=sleeping;if(sleeping)++_storage->capture_generation;
        return *this / _put(_events,FPCEvent{sleeping?FPCEvent::FPP_Suspend:FPCEvent::FPP_Resume,{},{}}) / &WorkerPower::run;
    }
};

// Runs a polkit CheckAuthorization for a gated method call on its own task.
// It must NOT run on the device task: dispatch is serial, so awaiting the
// check there would also block the polkit agent helper's own calls (the
// helper runs pam_fprintd, which calls Claim on this device). The helper's
// Claim would then sit in the queue for the full ~25s bus timeout before
// falling through to pam_unix - which is why the authentication dialog only
// surfaced at the exact moment the enroll client timed out. Upstream fprintd
// can afford a synchronous check because its blocking call keeps iterating
// the GLib main loop; this runtime has no nested loop, so the check lives
// here instead. On success the original call is re-queued into the device
// message queue and dispatched through the normal path.
class WorkerPolkitGate : public AsyncRoutine,
    private Queue2<std::queue<AsyncDBusMessage>>::CallbackPut
{
    AsyncDBusConnection _connection{};
    AsyncDBusMessage _msg{};
    Queue2<std::queue<AsyncDBusMessage>>* _queue{};
    std::function<void(const std::string&, bool)> _on_resolved{};
    std::string _cancellation_id{};

    AsyncDBusSendWithReply _send_with_reply{};
    AsyncDBusSend _send_message{};

    bool _check_sent{};
    bool _resolved{};

    std::string key() {
        const char* sender = dbus_message_get_sender(_msg);
        return std::string(sender == nullptr ? "" : sender) + ":"
             + std::to_string(dbus_message_get_serial(_msg));
    }

public:
    auto& operator ()(
        AsyncDBusConnection connection,
        AsyncDBusMessage msg,
        Queue2<std::queue<AsyncDBusMessage>>* queue,
        std::function<void(const std::string&, bool)> on_resolved)
    {
        _connection = std::move(connection);
        _msg = std::move(msg);
        _queue = queue;
        _on_resolved = std::move(on_resolved);
        _cancellation_id = "fingerpp-" + key();
        async_start(&WorkerPolkitGate::send_check);
        return *this;
    }

protected:
    AsyncDBusMessage queue2_put() override { return std::move(_msg); }
    void queue2_cancel_pending_put() override { }

    void async_finalize() noexcept override {
        if (_check_sent and not _resolved) {
            // The caller vanished or released mid-check; withdraw the pending
            // authentication so no orphaned dialog is left in the agent.
            AsyncDBusMessage cancel{dbus_message_new_method_call(
                "org.freedesktop.PolicyKit1",
                "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority",
                "CancelCheckAuthorization")};
            if (cancel != nullptr) {
                DBusMessageIter args{};
                dbus_message_iter_init_append(cancel, &args);
                const char* cid = _cancellation_id.c_str();
                dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &cid);
                dbus_connection_send(_connection, cancel, nullptr);
                dbus_connection_flush(_connection);
            }
        }
        AsyncRoutine::async_finalize();
    }

    Async send_check() {
        const char* sender = dbus_message_get_sender(_msg);
        if (sender == nullptr) {
            return deny();
        }

        AsyncDBusMessage call{
            dbus_message_new_method_call(
                "org.freedesktop.PolicyKit1",
                "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority",
                "CheckAuthorization")
        };
        if (call == nullptr) {
            return deny();
        }

        // CheckAuthorization(subject (sa{sv}), action_id s, details a{ss},
        //                    flags u, cancellation_id s)
        DBusMessageIter args{};
        dbus_message_iter_init_append(call, &args);

        // subject = ("system-bus-name", {"name": <sender unique name>})
        {
            DBusMessageIter subject{}, dict{}, entry{}, variant{};
            const char* kind = "system-bus-name";
            const char* key = "name";
            dbus_message_iter_open_container(&args, DBUS_TYPE_STRUCT, nullptr, &subject);
            dbus_message_iter_append_basic(&subject, DBUS_TYPE_STRING, &kind);
            dbus_message_iter_open_container(&subject, DBUS_TYPE_ARRAY, "{sv}", &dict);
            dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
            dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
            dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &sender);
            dbus_message_iter_close_container(&entry, &variant);
            dbus_message_iter_close_container(&dict, &entry);
            dbus_message_iter_close_container(&subject, &dict);
            dbus_message_iter_close_container(&args, &subject);
        }

        const char* action_id = "net.reactivated.fprint.device.enroll";
        dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &action_id);

        {
            DBusMessageIter details{};
            dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{ss}", &details);
            dbus_message_iter_close_container(&args, &details);
        }

        // flags: 1 = AllowUserInteraction, required for a prompt to appear
        dbus_uint32_t flags = 1;
        dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &flags);

        const char* cid = _cancellation_id.c_str();
        dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &cid);

        _check_sent = true;
        // The reply is sent only after the user answers the agent prompt, so
        // this needs much longer than the usual bus timeout.
        return *this
            / _send_with_reply(_connection, call, std::chrono::seconds(120))
            / &WorkerPolkitGate::check_done;
    }

    Async check_done() {
        _resolved = true;
        auto& reply = _send_with_reply.get_result();

        // Reply is (is_authorized b, is_challenge b, details a{ss}). Fail
        // closed: missing polkit, a timed-out or malformed reply, and an
        // explicit denial all take the same path.
        bool authorized = false;
        if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
            DBusMessageIter iter{}, result{};
            if (dbus_message_iter_init(reply, &iter) == TRUE
                and dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRUCT) {
                dbus_message_iter_recurse(&iter, &result);
                if (dbus_message_iter_get_arg_type(&result) == DBUS_TYPE_BOOLEAN) {
                    dbus_bool_t v = FALSE;
                    dbus_message_iter_get_basic(&result, &v);
                    authorized = (v == TRUE);
                }
            }
        }

        if (not authorized) {
            return deny();
        }

        // Mark the call authorized, then hand it back to the device dispatch
        // loop where it re-runs the normal per-method gate.
        _on_resolved(key(), true);
        _queue->put(this) >> JINX_IGNORE_RESULT;
        return async_return();
    }

    Async deny() {
        _on_resolved(key(), false);
        AsyncDBusMessage reply{
            dbus_message_new_error(_msg, "net.reactivated.Fprint.Error.PermissionDenied", "not authorized")
        };
        return *this / _send_message(_connection, reply) / &WorkerPolkitGate::async_return;
    }
};

class WorkerDevice : public AsyncDBusObject {
    Queue<std::queue<FPCEvent>>* _event_queue{};
    Queue<std::queue<FPCEvent>>* _image_queue{};
    fingerpp::Manager* _manager{};
    FingerprintStorage* _storage{};
    std::string _dbus_path{};

    bool _claimed{};
    std::string _claimed_sender{};
    std::string _claimed_user{};

    TaskPtr _enroll_verify_task{};
    TaskPtr _name_owner_chaged_task{};

    std::string _device_name{};
    int _num_enroll_stages{};
    std::string _scan_type{};

    DeviceState _device_state{};

    // Finger name to report in VerifyFingerSelected, held across the await on
    // the VerifyStart method return (see enroll_verify_start).
    std::string _verify_finger_selected{};

    AsyncDBusSend _send_message{};
    AsyncDBusSendWithReply _send_with_reply{};
    Queue<std::queue<FPCEvent>>::Put _put_image{};
    Queue<std::queue<FPCEvent>>::Put _put_event{};

    // Polkit authorization gate state, keyed by "<sender>:<serial>" of the
    // gated call (serials are per-connection, so the sender must be part of
    // the key). A 'pending' entry means a WorkerPolkitGate task owns the
    // check; 'authorized' means the call was re-queued and may proceed;
    // 'finished' entries are pruned lazily because a task cannot remove its
    // own map entry without a use-after-free.
    struct AuthGate {
        TaskPtr task{};
        std::string sender{};
        enum class State { pending, authorized, finished } state{State::pending};
    };
    std::unordered_map<std::string, AuthGate> _auth_gates{};

public:
    WorkerDevice() = default;

    auto& operator ()(
        Queue<std::queue<FPCEvent>>* event_queue,
        Queue<std::queue<FPCEvent>>* image_queue,
        fingerpp::Manager* manager, 
        FingerprintStorage* storage,
        const std::string& device_id) 
    {
        _event_queue = event_queue;
        _image_queue = image_queue;
        _manager = manager;
        _storage = storage;
        _dbus_path = manager->register_device();
        _device_state._connection=manager->get_dbus().get_connection();_device_state._path=_dbus_path;

        add_node(_dbus_path, [&](AsyncDBusNode& node){
            node.add_interface("net.reactivated.Fprint.Device", [&](AsyncDBusInterface& iface){
                iface.add_method("ListEnrolledFingers", "s", "as", &WorkerDevice::list_enrolled_fingers);
                iface.add_method("DeleteEnrolledFingers", "s", "", &WorkerDevice::delete_enrolled_fingers);
                iface.add_method("DeleteEnrolledFingers2", "", "", &WorkerDevice::delete_enrolled_fingers2);
                iface.add_method("DeleteEnrolledFinger", "s", "", &WorkerDevice::delete_enrolled_finger);

                iface.add_method("Claim", "s", "", &WorkerDevice::claim);
                iface.add_method("Release", "", "", &WorkerDevice::release);

                iface.add_method("VerifyStart", "s", "", &WorkerDevice::enroll_verify_start);
                iface.add_method("VerifyStop", "", "", &WorkerDevice::enroll_verify_stop);

                iface.add_signal("VerifyFingerSelected", "s");
                iface.add_signal("VerifyStatus", "sb");

                iface.add_method("EnrollStart", "s", "", &WorkerDevice::enroll_verify_start);
                iface.add_method("EnrollStop", "", "", &WorkerDevice::enroll_verify_stop);

                iface.add_signal("EnrollStatus", "sb");

                iface.add_property("name", "s", "read");
                iface.add_property("num-enroll-stages", "i", "read");
                iface.add_property("scan-type", "s", "read");
                iface.add_property("finger-present", "b", "read");
                iface.add_property("finger-needed", "b", "read");
            });
        });

        add_method("org.freedesktop.DBus", "NameOwnerChanged", "sss", &WorkerDevice::name_owner_changed);

        _device_name = device_id;
        _scan_type = "press";
        _num_enroll_stages = static_cast<int>(ENROLLMENT_POSITION_TEMPLATES);
        _device_state._finger_present = false;
        _device_state._finger_needed = false;

        // _enroll_task = manager->task_new<WorkerEnroll>(
        //     manager->get_dbus().get_connection(), 
        //     &_device_state, 
        //     _event_queue, 
        //     _image_queue, 
        //     _claimed_user, "a", _dbus_path, &_storage);

        AsyncDBusObject::operator()(_manager->get_dbus().get_connection());
        return *this;
    }

protected:

    void async_finalize() noexcept override {
        _manager->unregister_device(_dbus_path);
        if (_enroll_verify_task != nullptr) {
            async_cancel(_enroll_verify_task) >> JINX_IGNORE_RESULT;
            _enroll_verify_task.reset();
        }
        if (_name_owner_chaged_task != nullptr) {
            _name_owner_chaged_task->resume({}) >> JINX_IGNORE_RESULT;
            _name_owner_chaged_task.reset();
        }
        AsyncDBusObject::async_finalize();
    }

    Async get_uid() {
        auto& msg = get_message();
        const auto* sender = dbus_message_get_sender(msg);
        AsyncDBusMessage GetConnectionUnixUser{
            dbus_message_new_method_call(
                "org.freedesktop.DBus", 
                "/org/freedesktop/DBus", 
                "org.freedesktop.DBus", 
                "GetConnectionUnixUser")
        };

        DBusMessageIter args{};
        dbus_message_iter_init_append(GetConnectionUnixUser, &args);
        dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sender);

        return *this 
            / _send_with_reply(_connection, GetConnectionUnixUser, std::chrono::seconds(5)) 
            / &WorkerDevice::check_uid;
    }

    Async check_uid() {
        auto& unix_user = _send_with_reply.get_result();
        if (dbus_message_get_type(unix_user) == DBUS_MESSAGE_TYPE_ERROR) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.Internal", "get sender uid failed")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        // get uid
        dbus_uint32_t uid = UINT32_MAX;

        DBusMessageIter result{};
        if (dbus_message_iter_init(unix_user, &result) == FALSE or dbus_message_iter_get_arg_type(&result) != DBUS_TYPE_UINT32) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.Internal", "get sender uid failed")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }
        dbus_message_iter_get_basic(&result, &uid);

        // get username
        DBusMessageIter args{};
        dbus_message_iter_init(get_message(), &args);
        if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), DBUS_ERROR_INVALID_ARGS, "missing username")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }
        const char* username = nullptr;
        dbus_message_iter_get_basic(&args, &username);

        const auto* pwd = getpwuid(uid);

        if (pwd == nullptr) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.Internal", "get peer uid failed")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        if (username == nullptr or username[0] == 0) {
            username = pwd->pw_name;
        }

        if (strcmp(pwd->pw_name, username) != 0 and uid != 0) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.PermissionDenied", "permission denied")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        dbus_message_set_data(get_message(), MessageData::get_slot(), new MessageData{username}, MessageData::release);

        return AsyncDBusObject::handle_message();
    }

    Async check_sender() {
        auto& msg = get_message();

        if (not _claimed) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.ClaimDevice", "not claimed")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        // get sender
        const char* sender = dbus_message_get_sender(msg);

        if (_claimed_sender != sender) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.PermissionDenied", "this device claimed by another sender")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        return AsyncDBusObject::handle_message();
    }

    // Drop all authorization gates belonging to a sender: cancel pending
    // checks (which withdraws the agent prompt via CancelCheckAuthorization)
    // and tombstone already-authorized serials so a re-queued call sitting
    // in the message queue is dropped by check_polkit instead of spawning a
    // fresh check.
    void drop_auth_gates(const char* sender) {
        for (auto it = _auth_gates.begin(); it != _auth_gates.end();) {
            if (it->second.sender != sender) {
                ++it;
                continue;
            }
            if (it->second.state == AuthGate::State::authorized) {
                it->second.state = AuthGate::State::finished;
                ++it;
            } else {
                if (it->second.task != nullptr) {
                    async_cancel(it->second.task) >> JINX_IGNORE_RESULT;
                }
                it = _auth_gates.erase(it);
            }
        }
    }

    // Gate state-changing methods through polkit. The uid/claim checks above
    // prove only that the caller is who they claim to be - any local user
    // could enroll or delete their own fingerprints from an unattended
    // session with no prompt at all. Stock fprintd asks polkit before these
    // same operations via the "net.reactivated.fprint.device.enroll" action
    // (auth_self_keep: re-enter your own password), so this restores the
    // standard contract using the policy file every distro's fprintd package
    // already ships. Root is always authorised, so the documented
    // `sudo fprintd-enroll` flow keeps working without a prompt.
    //
    // The check runs on a side task (see WorkerPolkitGate) and the call is
    // re-queued once authorized; awaiting it here would park the serial
    // dispatch loop and starve the polkit helper's own Claim call, making
    // the agent dialog appear only after the client had timed out.
    Async check_polkit() {
        auto& msg = get_message();
        const char* sender = dbus_message_get_sender(msg);
        if (sender == nullptr) {
            AsyncDBusMessage reply{
                dbus_message_new_error(msg, "net.reactivated.Fprint.Error.PermissionDenied", "no sender")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        const std::string key = std::string(sender) + ":" + std::to_string(dbus_message_get_serial(msg));
        auto gate = _auth_gates.find(key);
        if (gate != _auth_gates.end()) {
            // This call was re-queued by its gate. Only an authorized call
            // proceeds; the denial path already replied to the caller.
            const bool authorized = gate->second.state == AuthGate::State::authorized;
            _auth_gates.erase(gate);
            if (not authorized) {
                return run();
            }
            const auto* method = dbus_message_get_member(msg);
            if (jinx::hash::hash_string(method) == jinx::hash::hash_string("DeleteEnrolledFingers")) {
                return get_uid();
            }
            return check_sender();
        }

        // Reject early if the device is claimed by someone else - the
        // re-queued call will fail check_sender() anyway, and skipping the
        // prompt avoids a dialog that can never succeed (upstream checks
        // claim state before asking polkit too).
        if (_claimed and _claimed_sender != sender) {
            AsyncDBusMessage reply{
                dbus_message_new_error(msg, "net.reactivated.Fprint.Error.AlreadyInUse", "device already in use")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        // Prune resolved gates left by earlier calls.
        for (auto it = _auth_gates.begin(); it != _auth_gates.end();) {
            if (it->second.state == AuthGate::State::finished) {
                it = _auth_gates.erase(it);
            } else {
                ++it;
            }
        }

        AsyncDBusMessage parked{dbus_message_ref(msg)};
        TaskPtr task = task_new<WorkerPolkitGate>(
            _connection, std::move(parked), get_message_queue(),
            [this](const std::string& done_key, bool authorized) {
                auto it = _auth_gates.find(done_key);
                if (it != _auth_gates.end()) {
                    it->second.state = authorized ? AuthGate::State::authorized
                                                  : AuthGate::State::finished;
                }
            });
        _auth_gates.emplace(key, AuthGate{task, sender});
        // The gate owns the reply now; keep dispatching other messages.
        return run();
    }

    Async handle_message() override {
        auto& msg = get_message();
        const auto* method = dbus_message_get_member(msg);
        const char* sender = dbus_message_get_sender(msg);

        using namespace jinx::hash;
        auto method_key = hash_string(method);

        switch(method_key) {
            case "ListEnrolledFingers"_hash:
            case "Claim"_hash:
                return get_uid();
            case "EnrollStart"_hash:
            case "DeleteEnrolledFinger"_hash:
            case "DeleteEnrolledFingers"_hash:
            case "DeleteEnrolledFingers2"_hash:
                return check_polkit();
            case "EnrollStop"_hash:
            case "VerifyStop"_hash:
            case "VerifyStart"_hash:
            case "Release"_hash:
                return check_sender();
            default: break;
        }
        return AsyncDBusObject::handle_message();
    }
    
    Async list_enrolled_fingers() {
        auto& msg = get_message();
        
        // get username
        auto* data = MessageData::get_data(msg);

        // reply
        AsyncDBusMessage reply{
            dbus_message_new_method_return(msg)
        };

        size_t num_enrolled = _storage->get_enrolled_count(data->_username);
        if (num_enrolled == 0) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.NoEnrolledPrints", "NoEnrolledPrints")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }
        DBusMessageIter args{};
        DBusMessageIter array{};
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "s", &array);
        _storage->foreach(data->_username, [&](Fingerprint& print){
            const char* name = print._name.c_str();
            dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &name);
            return false;
        });
        dbus_message_iter_close_container(&args, &array);
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    Async delete_enrolled_fingers() {
        auto& msg = get_message();
        
        // get username
        auto* data = MessageData::get_data(msg);

        if(!_storage->delete_all(data->_username)) {
            AsyncDBusMessage reply{dbus_message_new_error(msg,"net.reactivated.Fprint.Error.Internal","database save failed")};
            return *this / _send_message(_connection,reply) / &WorkerDevice::run;
        }
        
        AsyncDBusMessage reply{
            dbus_message_new_method_return(msg)
        };
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    Async delete_enrolled_fingers2() {
        auto& msg = get_message();

        if(!_storage->delete_all(_claimed_user)) {
            AsyncDBusMessage reply{dbus_message_new_error(msg,"net.reactivated.Fprint.Error.Internal","database save failed")};
            return *this / _send_message(_connection,reply) / &WorkerDevice::run;
        }
        
        AsyncDBusMessage reply{
            dbus_message_new_method_return(msg)
        };
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    Async delete_enrolled_finger() {
        auto& msg = get_message();

        // get name
        DBusMessageIter args{};
    
        if (dbus_message_iter_init(get_message(), &args) == FALSE or dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), DBUS_ERROR_INVALID_ARGS, "invalid argument")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }
        const char* name = nullptr;
        dbus_message_iter_get_basic(&args, &name);

        if (not _storage->delete_fingerprint(_claimed_user, name)) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.InvalidFingername", "invalid finger name")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }
        
        AsyncDBusMessage reply{
            dbus_message_new_method_return(msg)
        };
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    Async name_owner_changed() {
        auto& msg = get_message();
        DBusMessageIter args{};

        const char* name = nullptr;
        const char* old_owner = nullptr;
        const char* new_owner = nullptr;

        if (dbus_message_iter_init(msg, &args) == FALSE or dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
            return run();
        }

        dbus_message_iter_get_basic(&args, &name);

        if (dbus_message_iter_next(&args) == FALSE or dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
            return run();
        }

        dbus_message_iter_get_basic(&args, &old_owner);

        if (dbus_message_iter_next(&args) == FALSE or dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
            return run();
        }

        dbus_message_iter_get_basic(&args, &new_owner);

        if (new_owner[0] == 0) {
            syslog(LOG_AUTH | LOG_INFO, "disconnected");
            if (_enroll_verify_task != nullptr) {
                async_cancel(_enroll_verify_task) >> JINX_IGNORE_RESULT;
                _enroll_verify_task.reset();
                // A cancelled task can leave a pending Get on _image_queue;
                // clear it so a later Put cannot wake a dead awaitable
                // (PendingGetError).
                _image_queue->reset();
            }
            drop_auth_gates(old_owner);
            _claimed = false;
            _claimed_sender.clear();
            _claimed_user.clear();
            // The cancelled task cannot consume EnrollVerifyStop, so stop
            // the sensor directly (no-op if it was already idle).
            return *this / _put_event(_event_queue, FPCEvent{FPCEvent::FPP_StopSensor, {}, {}}) / &WorkerDevice::run;
        }

        return run();
    }

    Async claim() {
        auto& msg = get_message();

        if (_claimed) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.AlreadyInUse", "device already claimed")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        // get username
        auto* data = MessageData::get_data(msg);

        // get sender
        const char* sender = dbus_message_get_sender(msg);

        // add match
        std::string rule{"type='signal', interface='org.freedesktop.DBus', member='NameOwnerChanged', arg0='"};
        rule.append(sender);
        rule.append("'");

        _name_owner_chaged_task = task_new<WorkerListen>(_connection, get_message_queue(), rule);

        _claimed = true;
        _claimed_sender = sender;
        _claimed_user = data->_username;

        AsyncDBusMessage reply{
            dbus_message_new_method_return(msg)
        };
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    Async release() {
        auto& msg = get_message();
        const char* sender = dbus_message_get_sender(msg);

        if (_name_owner_chaged_task != nullptr) {
            _name_owner_chaged_task->resume({}) >> JINX_IGNORE_RESULT;
            _name_owner_chaged_task.reset();
        }

        if (_enroll_verify_task != nullptr) {
            async_cancel(_enroll_verify_task) >> JINX_IGNORE_RESULT;
            _enroll_verify_task.reset();
        }

        // A release during a pending check must not leave an orphaned agent
        // prompt or let a late authorization re-queue the gated call.
        drop_auth_gates(sender);

        _claimed = false;
        _claimed_sender.clear();
        _claimed_user.clear();

        AsyncDBusMessage reply{
            dbus_message_new_method_return(msg)
        };
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    Async enroll_verify_start() {
        const char* method = dbus_message_get_member(get_message());
        bool is_verify = strcmp(method, "VerifyStart") == 0;
        if(!_storage->reader_ready || _storage->sleeping) {
            AsyncDBusMessage reply{dbus_message_new_error(get_message(),"net.reactivated.Fprint.Error.Internal","reader session is recovering")};
            return *this / _send_message(_connection,reply) / &WorkerDevice::run;
        }

        if (_enroll_verify_task != nullptr) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.AlreadyInUse", "device already in use")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        // get finger name
        DBusMessageIter args{};
        if (dbus_message_iter_init(get_message(), &args) == FALSE or dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), DBUS_ERROR_INVALID_ARGS, "invalid argument")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }
        const char* finger_name = nullptr;
        dbus_message_iter_get_basic(&args, &finger_name);

        // std::cout << finger_name << std::endl;

        bool exists = _storage->check(_claimed_user, finger_name);
        // if (not is_verify and exists) {
        //     AsyncDBusMessage reply{
        //         dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.InvalidFingername", "already enrolled")
        //     };
        //     return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        // }
        if (is_verify and not Fingerprint::is_any(finger_name) and not exists) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.NoEnrolledPrints", "NoEnrolledPrints")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        _enroll_verify_task = task_new<WorkerEnrollVerify>(
            _manager, 
            &_device_state, 
            _event_queue, 
            _image_queue,
            _claimed_user, 
            finger_name, 
            _dbus_path, 
            _storage,
            is_verify);

        // VerifyFingerSelected must be emitted for a prompt to appear anywhere:
        // pam_fprintd uses it to produce the PAM info message "Place your
        // finger on <device>", and GNOME Shell turns that message into the
        // "(or place finger on reader)" hint under the password field.
        // Upstream declared the signal in the interface above and never sent
        // it, so verification worked while the reader looked dead.
        //
        // ORDERING IS PART OF THE CONTRACT. pam_fprintd calls VerifyStart
        // asynchronously and only sets its internal `verify_started` flag in
        // the method-return callback. Its VerifyFingerSelected handler starts
        // with:
        //
        //     if (!data->verify_started) { "Unexpected ... signal"; return 0; }
        //
        // so a signal that reaches the client BEFORE the method return is
        // parsed, logged as unexpected, and dropped - no PAM message, no GNOME
        // hint. Emitting it first therefore looks correct on the wire and still
        // produces no prompt.
        //
        // Both the reply and the signal go out via dbus_connection_send(),
        // which appends to a single ordered outgoing queue, and D-Bus preserves
        // per-sender ordering. So the reply is awaited first and the signal is
        // emitted from the continuation below, guaranteeing the client sees
        // return-then-signal.
        AsyncDBusMessage reply{
            dbus_message_new_method_return(get_message())
        };

        if (is_verify) {
            _verify_finger_selected = finger_name;
            return *this
                / _send_message(_connection, reply)
                / &WorkerDevice::send_verify_finger_selected;
        }

        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    // Continuation of enroll_verify_start() for the verify case: runs only
    // after the VerifyStart method return has been queued, so pam_fprintd has
    // already set verify_started by the time this signal reaches it.
    Async send_verify_finger_selected() {
        AsyncDBusMessage finger_signal{
            dbus_message_new_signal(
                _dbus_path.c_str(),
                "net.reactivated.Fprint.Device",
                "VerifyFingerSelected")
        };
        if (finger_signal == nullptr) {
            return run();
        }
        const char* finger_name = _verify_finger_selected.c_str();
        DBusMessageIter sig_iter{};
        dbus_message_iter_init_append(finger_signal, &sig_iter);
        dbus_message_iter_append_basic(&sig_iter, DBUS_TYPE_STRING, &finger_name);
        return *this / _send_message(_connection, finger_signal) / &WorkerDevice::run;
    }

    Async enroll_verify_stop() {
        if (_enroll_verify_task == nullptr) {
            AsyncDBusMessage reply{
                dbus_message_new_error(get_message(), "net.reactivated.Fprint.Error.NoActionInProgress", "invalid state")
            };
            return *this / _send_message(_connection, reply) / &WorkerDevice::run;
        }

        AsyncDBusMessage reply{
            dbus_message_new_method_return(get_message())
        };
        return *this / _send_message(_connection, reply) / &WorkerDevice::send_enroll_stop;
    }

    Async send_enroll_stop() {
        _enroll_verify_task.reset();
        return *this / _put_image(_image_queue, FPCEvent{FPCEvent::FPP_EnrollVerifyStop, {}, {}}) / &WorkerDevice::run;
    }

    // Capture workers publish finger-present/finger-needed PropertiesChanged.

    Async handle_get_property() override {
        auto& msg = get_message();
        AsyncDBusMessage reply{};
        char* intarface{nullptr};

        DBusMessageIter args{};
        if (dbus_message_iter_init(msg, &args) == FALSE or dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
            reply.reset(dbus_message_new_error_printf(msg, DBUS_ERROR_INVALID_ARGS, "invalid argument"));
        } else {
            dbus_message_iter_get_basic(&args, &intarface);

            const char* name = nullptr;
            dbus_message_iter_next(&args);
            if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
                reply.reset(dbus_message_new_error_printf(msg, DBUS_ERROR_INVALID_ARGS, "invalid argument"));
                return *this / _send_message(_connection, reply) / &WorkerDevice::run;
            }
            dbus_message_iter_get_basic(&args, &name);

            using namespace hash;

            auto name_key = hash_string(name);
            switch(name_key) {
                case "name"_hash:
                {
                    DBusMessageIter result{};
                    DBusMessageIter variant{};
                    const char* device_name = _device_name.c_str();

                    reply.reset(dbus_message_new_method_return(msg));
                    dbus_message_iter_init_append(reply, &result);
                    dbus_message_iter_open_container(&result, DBUS_TYPE_VARIANT, "s", &variant);
                    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &device_name);
                    dbus_message_iter_close_container(&result, &variant);
                }
                    break;
                case "num-enroll-stages"_hash:
                {
                    DBusMessageIter result{};
                    DBusMessageIter variant{};

                    reply.reset(dbus_message_new_method_return(msg));
                    dbus_message_iter_init_append(reply, &result);
                    dbus_message_iter_open_container(&result, DBUS_TYPE_VARIANT, "i", &variant);
                    dbus_message_iter_append_basic(&variant, DBUS_TYPE_INT32, &_num_enroll_stages);
                    dbus_message_iter_close_container(&result, &variant);
                }
                    break;
                case "scan-type"_hash:
                {
                    DBusMessageIter result{};
                    DBusMessageIter variant{};
                    const char* scan_type = _scan_type.c_str();

                    reply.reset(dbus_message_new_method_return(msg));
                    dbus_message_iter_init_append(reply, &result);
                    dbus_message_iter_open_container(&result, DBUS_TYPE_VARIANT, "s", &variant);
                    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &scan_type);
                    dbus_message_iter_close_container(&result, &variant);
                }
                    break;
                case "finger-present"_hash:
                {
                    DBusMessageIter result{};
                    DBusMessageIter variant{};
                    dbus_bool_t present = _device_state._finger_present ? TRUE : FALSE;

                    reply.reset(dbus_message_new_method_return(msg));
                    dbus_message_iter_init_append(reply, &result);
                    dbus_message_iter_open_container(&result, DBUS_TYPE_VARIANT, "b", &variant);
                    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &present);
                    dbus_message_iter_close_container(&result, &variant);
                }
                    break;
                case "finger-needed"_hash:
                {
                    DBusMessageIter result{};
                    DBusMessageIter variant{};
                    dbus_bool_t needed = _device_state._finger_needed ? TRUE : FALSE;

                    reply.reset(dbus_message_new_method_return(msg));
                    dbus_message_iter_init_append(reply, &result);
                    dbus_message_iter_open_container(&result, DBUS_TYPE_VARIANT, "b", &variant);
                    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &needed);
                    dbus_message_iter_close_container(&result, &variant);
                }
                    break;
                default:
                    reply.reset(dbus_message_new_error_printf(msg, DBUS_ERROR_UNKNOWN_PROPERTY, "no such property"));
            }
        }
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }

    Async handle_get_all_properties() override {
        auto& msg = get_message();
        AsyncDBusMessage reply(
            dbus_message_new_method_return(msg)
        );
        const char* name = nullptr;
        const char* string_value = nullptr;
        dbus_bool_t bool_value = FALSE;

        DBusMessageIter iter{};
        dbus_message_iter_init_append(reply, &iter);
        
        DBusMessageIter sub{};
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &sub);
        
        DBusMessageIter keyvalue{};
        DBusMessageIter value{};

        dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, nullptr, &keyvalue);
        name = "name";
        string_value = _device_name.c_str();
        dbus_message_iter_append_basic(&keyvalue, DBUS_TYPE_STRING, &name);
        dbus_message_iter_open_container(&keyvalue, DBUS_TYPE_VARIANT, "s", &value);
        dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &string_value);
        dbus_message_iter_close_container(&keyvalue, &value);
        dbus_message_iter_close_container(&sub, &keyvalue);

        dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, nullptr, &keyvalue);
        name = "num-enroll-stages";
        dbus_message_iter_append_basic(&keyvalue, DBUS_TYPE_STRING, &name);
        dbus_message_iter_open_container(&keyvalue, DBUS_TYPE_VARIANT, "i", &value);
        dbus_message_iter_append_basic(&value, DBUS_TYPE_INT32, &_num_enroll_stages);
        dbus_message_iter_close_container(&keyvalue, &value);
        dbus_message_iter_close_container(&sub, &keyvalue);

        dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, nullptr, &keyvalue);
        name = "scan-type";
        string_value = _scan_type.c_str();
        dbus_message_iter_append_basic(&keyvalue, DBUS_TYPE_STRING, &name);
        dbus_message_iter_open_container(&keyvalue, DBUS_TYPE_VARIANT, "s", &value);
        dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &string_value);
        dbus_message_iter_close_container(&keyvalue, &value);
        dbus_message_iter_close_container(&sub, &keyvalue);

        dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, nullptr, &keyvalue);
        name = "finger-present";
        bool_value = _device_state._finger_present ? TRUE : FALSE;
        dbus_message_iter_append_basic(&keyvalue, DBUS_TYPE_STRING, &name);
        dbus_message_iter_open_container(&keyvalue, DBUS_TYPE_VARIANT, "b", &value);
        dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &bool_value);
        dbus_message_iter_close_container(&keyvalue, &value);
        dbus_message_iter_close_container(&sub, &keyvalue);

        dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, nullptr, &keyvalue);
        name = "finger-needed";
        bool_value = _device_state._finger_needed ? TRUE : FALSE;
        dbus_message_iter_append_basic(&keyvalue, DBUS_TYPE_STRING, &name);
        dbus_message_iter_open_container(&keyvalue, DBUS_TYPE_VARIANT, "b", &value);
        dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &bool_value);
        dbus_message_iter_close_container(&keyvalue, &value);
        dbus_message_iter_close_container(&sub, &keyvalue);

        dbus_message_iter_close_container(&iter, &sub);
        return *this / _send_message(_connection, reply) / &WorkerDevice::run;
    }
};

class TLSEventReader : public AsyncRoutine {
    BIOPipePtr _pipe{};
    fpc::EventFramer _framer;
    Queue<std::queue<FPCEvent>>* _event_queue{nullptr};

    enum {
        ModeInitial,
        ModeRecv,
    } _mode{ModeInitial};

    size_t _received_length{0};
    size_t _event_length{0};
    std::vector<FPCBuffer> _buffers;
    FPCBuffer _buffer{};

    Queue<std::queue<FPCEvent>>::Put _put_event{};

public:
    TLSEventReader& operator ()(BIOPipePtr& pipe, Queue<std::queue<FPCEvent>>* queue) {
        _pipe = pipe;
        _event_queue = queue;
        async_start(&TLSEventReader::accept);
        return *this;
    }

protected:
    void async_finalize() noexcept override {
        _put_event.reset();
        _buffers.clear();
        AsyncRoutine::async_finalize();
    }

    Async handle_error(const error::Error& error) override {
        auto state = AsyncRoutine::handle_error(error);
        if (state != ControlState::Raise) {
            return state;
        }

        if (error.category() == category_awaitable()
            and error.as<ErrorAwaitable>() == ErrorAwaitable::Cancelled)
        {
            return async_return();
        }

        // TLS state is tied to the current USB session. A suspend can leave
        // OpenSSL with a partial record or handshake. Notify the controller
        // through the normal event path: Queue::reset() resumes and clears
        // waiters at once, which is unsafe while one of them is being reused.
        jinx_log_warning() << "TLS transport failed: " << error.message() << std::endl;
        return *this
            / _put_event(_event_queue, FPCEvent{FPCEvent::FPP_TransportFailed, {}, {}, error})
            / &TLSEventReader::async_return;
    }

    Async accept() {
        return *this / _pipe->_ssl_server.accept() / &TLSEventReader::ready;
    }

    Async ready() {
        return *this / _put_event(_event_queue, FPCEvent{ FPCEvent::TLS_Ready, {} }) / &TLSEventReader::read;
    }

    Async read() {
        _buffer = _pipe->_allocator.allocate(FPCBufferConfig{});
        if (_buffer == nullptr) {
            error::fatal("out of memory");
        }
        return *this / _pipe->_ssl_server.read(&_buffer.get()->view()) / &TLSEventReader::process;
    }

    Async process() {
        try{auto view=_buffer->slice_for_consumer();_framer.feed(view.data(),view.size());_buffer.reset();}
        catch(const std::exception&){return async_throw(make_error(LIBUSB_ERROR_IO));}
        return dispatch_frames();
    }
    Async dispatch_frames(){
        try{auto frame=_framer.next();if(!frame)return read();
            return *this / _put_event(_event_queue,frame_event(std::move(*frame),_pipe)) / &TLSEventReader::dispatch_frames;
        }catch(const std::exception&){return async_throw(make_error(LIBUSB_ERROR_IO));}
    }
};

// Read data from USB device
class USBInput : public AsyncRoutine {
    libusb_device_handle* _handle{};
    libusb_endpoint_descriptor _endpoint{};
    libusb_transfer* _transfer{};
    BIOPipePtr _pipe;
    fpc::EventFramer _framer;
    Queue<std::queue<FPCEvent>>* _event_queue{nullptr};

    enum {
        ModeInitial,
        ModeRecv,
    } _mode{ModeInitial};

    size_t _received_length{0};
    size_t _event_length{0};
    std::vector<FPCBuffer> _buffers;
    size_t _buffer_index{};

    fpcusb::USBBulkTransfer _bulk_transfer{};
    Queue<std::queue<FPCEvent>>::Put _put_event{};

public:
    USBInput& operator ()(
        libusb_device_handle* handle, 
        libusb_endpoint_descriptor& endpoint, 
        BIOPipePtr& pipe,
        Queue<std::queue<FPCEvent>>* queue) 
    {
        _handle = handle;
        _endpoint = endpoint;
        _pipe = pipe;
        _event_queue = queue;
        if (_transfer == nullptr) {
            _transfer = libusb_alloc_transfer(0);
        }
        async_start(&USBInput::prepare);
        return *this;
    }

    USBInput() = default;

    ~USBInput() override {
        if (_transfer != nullptr) {
            libusb_free_transfer(_transfer);
            _transfer = nullptr;
        }
    }

    JINX_NO_COPY_NO_MOVE(USBInput);

protected:
    void async_finalize() noexcept override {
        _put_event.reset();
        _pipe.reset();
        _buffers = {};
        AsyncRoutine::async_finalize();
    }

    Async handle_error(const error::Error& error) override {
        auto state = AsyncRoutine::handle_error(error);
        if (state != ControlState::Raise) {
            return state;
        }

        if (error.category() == category_awaitable()
            and error.as<ErrorAwaitable>() == ErrorAwaitable::Cancelled)
        {
            return async_return();
        }

        if (error.category() == jinx::usb::category_usb()
            or error.category() == jinx::usb::category_transfer())
        {
            jinx_log_warning() << "USB input failed: " << error.message() << std::endl;
            return *this
                / _put_event(_event_queue, FPCEvent{FPCEvent::FPP_TransportFailed, {}, {}, error})
                / &USBInput::async_return;
        }

        return state;
    }

    Async prepare() {
        auto buf = _pipe->_allocator.allocate(FPCBufferConfig{});
        if (buf == nullptr) {
            error::fatal("out of memory");
        }
        _buffers.emplace_back(std::move(buf));
        return recv();
    }

    Async recv() {
        assert(not _buffers.empty());
        auto& buffer = _buffers.back();
        auto iobuf = buffer->slice_for_producer();
        if (iobuf._size == 0) {
            return prepare();
        }
        return *this 
            / _bulk_transfer(_handle, _endpoint.bEndpointAddress, iobuf, std::chrono::seconds(0)) 
            / &USBInput::parse;
    }

    Async parse() {
        auto length=_bulk_transfer.get_result();auto& buffer=_buffers.back();
        buffer->commit(length).abort_on(Failed_,"buffer overflow");
        try{auto view=buffer->slice_for_consumer();_framer.feed(view.data(),view.size());}
        catch(const std::exception&){return async_throw(make_error(LIBUSB_ERROR_IO));}
        _buffers.clear();return dispatch_frames();
    }
    Async dispatch_frames(){
        try{auto frame=_framer.next();if(!frame)return prepare();
            auto event=frame_event(std::move(*frame),_pipe);
            if(event._ev.code==ev_tls){_buffers=std::move(event._buffers);_buffer_index=0;return handle_tls_data();}
            return *this / _put_event(_event_queue,std::move(event)) / &USBInput::dispatch_frames;
        }catch(const std::exception&){return async_throw(make_error(LIBUSB_ERROR_IO));}
    }

    Async handle_tls_data() {
        if (_buffer_index >= _buffers.size()) {
            _buffers.clear();
            return dispatch_frames();
        }
        auto& buffer = _buffers.at(_buffer_index);
        ++ _buffer_index;
        return *this / _pipe->_bio_server.write(&buffer.get()->view()) / &USBInput::handle_tls_data;
    }
};

// Write data into USB device
class USBOutput : public AsyncRoutine {
    libusb_device_handle* _handle{};
    libusb_endpoint_descriptor _endpoint;
    BIOPipePtr _pipe{};
    Queue<std::queue<FPCEvent>>* _event_queue{nullptr};
    
    HeapBuffer _buffer{};
    buffer::BufferView _payload{};

    fpcusb::USBControlTransfer _control_transfer{};
    Queue<std::queue<FPCEvent>>::Put _put_event{};

public:
    USBOutput& operator ()(
        libusb_device_handle* handle, 
        libusb_endpoint_descriptor& endpoint, 
        BIOPipePtr& pipe,
        Queue<std::queue<FPCEvent>>* queue)
    {
        _handle = handle;
        _endpoint = endpoint;
        _pipe = pipe;
        _event_queue = queue;

        auto size = LIBUSB_CONTROL_SETUP_SIZE + _endpoint.wMaxPacketSize;
        _buffer = HeapBuffer{
            (unsigned char*)malloc(size)}; // NOLINT
        _payload = {_buffer.get() + LIBUSB_CONTROL_SETUP_SIZE, _endpoint.wMaxPacketSize, 0, 0};
        async_start(&USBOutput::read_bio_stream);
        return *this;
    }

protected:
    void async_finalize() noexcept override {
        _put_event.reset();
        _pipe.reset();
        _buffer.reset();
        AsyncRoutine::async_finalize();
    }

    Async handle_error(const error::Error& error) override {
        auto state = AsyncRoutine::handle_error(error);
        if (state != ControlState::Raise) {
            return state;
        }

        if (error.category() == category_awaitable()
            and error.as<ErrorAwaitable>() == ErrorAwaitable::Cancelled)
        {
            return async_return();
        }

        if (error.category() == jinx::usb::category_usb()
            or error.category() == jinx::usb::category_transfer())
        {
            jinx_log_warning() << "USB output failed: " << error.message() << std::endl;
            return *this
                / _put_event(_event_queue, FPCEvent{FPCEvent::FPP_TransportFailed, {}, {}, error})
                / &USBOutput::async_return;
        }

        return state;
    }

    Async read_bio_stream() {
        return *this / _pipe->_bio_server.read(&_payload) / &USBOutput::send;
    }

    Async send() {
        if (_payload.size() == 0) {
            _payload.reset_empty();
            return read_bio_stream();
        }

        auto size = std::min(_payload.size(), (size_t)_endpoint.wMaxPacketSize);

        libusb_fill_control_setup(
            _buffer, 
            CTRL_HOST_TO_DEVICE, 
            cmd_tls_data, 
            0x0001, 0, size);
        _payload.consume(size) >> JINX_IGNORE_RESULT;
        return *this / _control_transfer(_handle, _buffer.get(), std::chrono::seconds(10)) / &USBOutput::send;
    }
};

class SessionWatchdog : public AsyncRoutine {
    bool* _ready{};
    Queue<std::queue<FPCEvent>>* _events{};
    async::Sleep _sleep;
    Queue<std::queue<FPCEvent>>::Put _put;
public:
    SessionWatchdog& operator()(bool* ready,Queue<std::queue<FPCEvent>>* events){_ready=ready;_events=events;async_start(&SessionWatchdog::wait);return *this;}
protected:
    Async wait(){return *this / _sleep(std::chrono::seconds(15)) / &SessionWatchdog::expired;}
    Async expired(){if(*_ready)return async_return();
        return *this / _put(_events,FPCEvent{FPCEvent::FPP_TransportFailed,{},{},make_error(LIBUSB_ERROR_TIMEOUT)}) / &SessionWatchdog::async_return;}
};

class USBReaper : public AsyncRoutine {
    async::Sleep _sleep;
public:
    USBReaper& operator()(){async_start(&USBReaper::reap);return *this;}
protected:
    Async reap(){
        fpcusb::drain_usb_closes();
        if(!fpcusb::has_deferred_usb_closes())return async_return();
        return *this / _sleep(std::chrono::milliseconds(5)) / &USBReaper::reap;
    }
};

class WorkerControl : public AsyncRoutine 
{
    fingerpp::Manager* _manager{};
    fingerpp::USBDeviceInfo* _device_info{};
    USBDeviceHandle _handle;
    libusb_interface_descriptor _interface{};
    libusb_endpoint_descriptor _endpoint;

    std::vector<unsigned char> _tls_key{};
    BIOPipePtr _pipe;
    Queue<std::queue<FPCEvent>> _event_queue{0};
    Queue<std::queue<FPCEvent>> _image_queue{0};
    unsigned char _control_buffer[LIBUSB_CONTROL_SETUP_SIZE + 1000]{};
    std::vector<TaskPtr> _tasks{};
    bool _ready{};
    bool _capture_active{};
    uint64_t _capture_generation{};
    uint32_t _arm_token=0x17112f10;
    uint16_t _reader_identity{},_optional_format{};
    std::string _firmware;
    std::chrono::steady_clock::time_point _last_arm{},_last_image{};
    TaskPtr _device_task{},_power_task{};
    bool _suspended{};
    FingerprintStorage _storage{};
    std::string device_unique_id{};

    Queue<std::queue<FPCEvent>>::Get _get_event{};
    Queue<std::queue<FPCEvent>>::Put _put_image{};
    fpcusb::USBControlTransfer _control_transfer{};
    async::Sleep _sleep{};
    size_t _recovery_attempt{};
    error::Error _recovery_error{};
    std::chrono::steady_clock::time_point _recovery_started{};

public:
    WorkerControl& operator ()(
        fingerpp::Manager* manager,
        fingerpp::USBDeviceInfo* info,
        USBDeviceHandle&& handle) 
    {
        _manager = manager;
        _device_info = info;
        _handle = std::move(handle);
        _ready = false;
        _device_info->_attached = true;
        _power_task=_manager->get_loop().task_new<WorkerPower>(&_manager->get_loop(),_manager->get_dbus().get_connection(),&_event_queue,&_storage);
        if (_handle == nullptr) {
            async_start(&WorkerControl::schedule_recovery);
        } else {
            async_start(&WorkerControl::init);
        }
        return *this;
    }

protected:
    static std::vector<unsigned char> event_bytes(FPCEvent& event) {
        std::vector<unsigned char> bytes;
        for(auto& buffer:event._buffers){auto view=buffer->slice_for_consumer();
            if(view.size()>20000-bytes.size())throw std::runtime_error("oversized FPC event");
            auto* data=static_cast<const unsigned char*>(view.data());bytes.insert(bytes.end(),data,data+view.size());}
        return bytes;
    }
    static bool find_endpoint(libusb_device* dev, libusb_interface_descriptor* interface, libusb_endpoint_descriptor* endpoint) 
    {
        struct libusb_config_descriptor* config_desc;
        int ret = libusb_get_active_config_descriptor(dev, &config_desc);
        if (ret < 0) {
            return false;
        }

        bool found = false;
        for (int intf_idx = 0 ; intf_idx < config_desc->bNumInterfaces; ++intf_idx) {
            const struct libusb_interface* iface = &config_desc->interface[intf_idx];
            for (int intf_desc_idx = 0 ; intf_desc_idx < iface->num_altsetting; ++intf_desc_idx) {
                const struct libusb_interface_descriptor* iface_desc = &iface->altsetting[intf_desc_idx];
                for (int endp_idx = 0 ; endp_idx < iface_desc->bNumEndpoints; ++endp_idx) {
                    const struct libusb_endpoint_descriptor* endp_desc = &iface_desc->endpoint[endp_idx];
                    if (endp_desc->bEndpointAddress == 0x82) {
                        *interface = *iface_desc;
                        *endpoint = *endp_desc;
                        found = true;
                        break;
                    }
                }
                if (found) break;
            }
            if (found) break;
        }
        libusb_free_config_descriptor(config_desc);
        return found;
    }

    void cleanup_device(bool remove_device=false) noexcept {
        _storage.reader_ready=false;
        // Cancel all queue users before clearing queued values. Resetting a
        // Jinx queue first resumes its waiters while their operations are
        // still linked, which can make a later reused Get fail with
        // PendingGetError.
        if (remove_device && _device_task != nullptr) {
            async_cancel(_device_task) >> JINX_IGNORE_RESULT;
            _device_task.reset();
        }

        for (auto& task : _tasks) {
            async_cancel(task) >> JINX_IGNORE_RESULT;
        }
        _tasks.clear();

        _get_event.reset();
        _put_image.reset();
        _event_queue.reset();
        _image_queue.reset();

        std::fill(_tls_key.begin(), _tls_key.end(), 0);
        _tls_key.clear();

        _control_transfer.release();
        fpcusb::defer_usb_close(_handle.release(),_interface.bLength?_interface.bInterfaceNumber:-1);
        if(fpcusb::has_deferred_usb_closes())_manager->get_loop().task_new<USBReaper>();
        _interface = {};
        _endpoint = {};
        _pipe.reset();
        _ready = false;
        _capture_active=false;
        ++_storage.capture_generation;
    }

    void async_finalize() noexcept override {
        if(_power_task){async_cancel(_power_task)>>JINX_IGNORE_RESULT;_power_task.reset();}
        cleanup_device(true);
        _device_info->_attached = false;
        AsyncRoutine::async_finalize();
    }

    std::chrono::milliseconds recovery_delay() const noexcept {
        static constexpr std::chrono::milliseconds delays[] = {
            std::chrono::milliseconds(500),
            std::chrono::seconds(1),
            std::chrono::seconds(2),
            std::chrono::seconds(5),
            std::chrono::seconds(10),
            std::chrono::seconds(30),
        };
        auto index = std::min(_recovery_attempt, std::size(delays) - 1);
        return delays[index];
    }

    Async schedule_recovery() {
        if(_recovery_attempt>=6){jinx_log_error()<<"fingerprint recovery exhausted";return async_return();}
        auto delay = recovery_delay();
        ++_recovery_attempt;
        jinx_log_warning() << "fingerprint sensor recovery attempt "
                           << _recovery_attempt << " in " << delay.count() << " ms" << std::endl;
        return *this / _sleep(delay) / &WorkerControl::reopen;
    }

    Async begin_recovery(const error::Error& error) {
        jinx_log_warning() << "fingerprint sensor session failed: "
                           << error.message() << std::endl;
        cleanup_device();
        _suspended=_storage.sleeping;
        if(_suspended)return get_event();
        return schedule_recovery();
    }

    Async notify_operation_failed(const error::Error& error) {
        _ready=false;_storage.reader_ready=false;
        _recovery_error = error;
        if (_device_task == nullptr || !_storage.operation_active) {
            return begin_recovery(error);
        }
        _recovery_started=std::chrono::steady_clock::now();
        return *this
            / _put_image(&_image_queue, FPCEvent{FPCEvent::FPP_TransportFailed, {}, {}, error})
            / &WorkerControl::yield_recovery;
    }

    Async yield_recovery() {
        return *this / _sleep(std::chrono::milliseconds(5)) / &WorkerControl::resume_recovery;
    }
    Async resume_recovery() {
        if(_storage.operation_active && std::chrono::steady_clock::now()-_recovery_started<std::chrono::seconds(5))
            return *this / _sleep(std::chrono::milliseconds(50)) / &WorkerControl::resume_recovery;
        return begin_recovery(_recovery_error);
    }

    Async reopen() {
        fpcusb::drain_usb_closes();
        if(fpcusb::has_deferred_usb_closes())
            return *this / _sleep(std::chrono::milliseconds(5)) / &WorkerControl::reopen;
        USBDeviceHandle handle{
            libusb_open_device_with_vid_pid(
                _manager->get_usb(),
                _device_info->_vendor,
                _device_info->_product)};
        if (handle == nullptr) {
            return schedule_recovery();
        }

        _handle = std::move(handle);
        _interface = {};
        _endpoint = {};
        jinx_log_info() << "fingerprint sensor reopened" << std::endl;
        return init();
    }

    Async handle_error(const error::Error& error) override {
        auto state = AsyncRoutine::handle_error(error);
        if (state != ControlState::Raise) {
            return state;
        }

        if (error.category() == category_awaitable()) {
            if (static_cast<ErrorAwaitable>(error.value()) == ErrorAwaitable::Cancelled) {
                return async_return();
            }
        } else if (error.category() == category_transfer()
                   or error.category() == category_usb()) {
            return notify_operation_failed(error);
        }

        return state;
    }

    Async init() {
        auto ret = find_endpoint(libusb_get_device(_handle), &_interface, &_endpoint);
        if (not ret) {
            jinx_log_error() << "endpoint not found\n";
            return async_throw(make_error(LIBUSB_ERROR_NOT_FOUND));
        }
        ret = libusb_claim_interface(_handle, _interface.bInterfaceNumber);
        if (ret < 0) {
            return async_throw(make_error(static_cast<libusb_error>(ret)));
        }

        // TODO cmd_get_unique_id
        device_unique_id = "fpc9201";

        return indicate_s_state();
    }

    Async indicate_s_state() {
        libusb_fill_control_setup( _control_buffer, CTRL_HOST_TO_DEVICE, cmd_indicate_s_state, 0x0010, 0x0000, 0);
        return *this 
            / _control_transfer(_handle, _control_buffer, std::chrono::seconds(10)) 
            / &WorkerControl::get_state;
    }

    Async get_state() {
        libusb_fill_control_setup( _control_buffer, CTRL_DEVICE_TO_HOST, cmd_get_state, 0x0000, 0x0000, 72);
        return *this 
            / _control_transfer(_handle, _control_buffer, std::chrono::seconds(10)) 
            / &WorkerControl::parse_state;
    }

    Async parse_state() {
        libusb_device_handle* handle = _handle.get();
        unsigned char* data = &_control_buffer[LIBUSB_CONTROL_SETUP_SIZE];
        if(_control_transfer.get_result()!=72)return async_throw(make_error(LIBUSB_ERROR_IO));

        printf("Version %d.%d.%d.%d\n", 
            data[0], data[1], 
            data[2], data[3]);
        
        // 21.26.2.x
        if (data[0] != 21 || data[1] != 26 || data[2] != 2) {
            jinx_log_error() << "firmware version mismatch\n";
            return async_return();
        }

        // init
        libusb_fill_control_setup( _control_buffer, CTRL_HOST_TO_DEVICE, cmd_init, 0x0001, 0x0000, 4);
        
        data[0] = 0x10;
        data[1] = 0x2f;
        data[2] = 0x11;
        data[3] = 0x17;
        return *this 
            / _control_transfer(handle, _control_buffer, std::chrono::seconds(30)) 
            / &WorkerControl::spawn;
    }

    Async spawn() {
        _tasks.emplace_back(task_new<SessionWatchdog>(&_ready,&_event_queue));
        _pipe = std::make_shared<BIOPipe>();

        _tasks.emplace_back(
            task_new<TLSEventReader>(_pipe, &_event_queue)
        );
        
        _tasks.emplace_back(
            task_new<USBOutput>(_handle, _endpoint, _pipe, &_event_queue)
        );
                
        _tasks.emplace_back(
            task_new<USBInput>(_handle, _endpoint, _pipe, &_event_queue)
        );
        
        return get_event();
    }

    Async get_event() {
        return *this /_get_event(&_event_queue) / &WorkerControl::handle_event;
    }

    Async handle_event() {
        auto& event = _get_event.get_result();
        if (event._type == FPCEvent::FPC_Event) {
            switch(event._ev.code) {
                case ev_hello:
                    break;
                case ev_init_result:
                {
                    auto bytes=event_bytes(event);
                    if((bytes.size()!=24 && bytes.size()!=26) || event._ev.unknown!=0)
                        return async_throw(make_error(LIBUSB_ERROR_IO));
                    auto be16=[&](size_t offset){return uint16_t(uint16_t(bytes[offset])<<8|bytes[offset+1]);};
                    _reader_identity=be16(0);_storage.hardware_id=be16(2);
                    if(!_reader_identity || (_storage.hardware_id!=0x0111 && _storage.hardware_id!=0x0121) || be16(4)!=112 || be16(6)!=88)
                        return async_throw(make_error(LIBUSB_ERROR_NOT_SUPPORTED));
                    _firmware.assign(bytes.begin()+8,bytes.begin()+24);
                    _optional_format=bytes.size()==26?be16(24):0;
                    jinx_log_info()<<"profile300 reader HWID="<<std::hex<<_storage.hardware_id<<std::dec<<" firmware="<<_firmware;
                    libusb_fill_control_setup( _control_buffer, CTRL_DEVICE_TO_HOST, cmd_get_tls_key, 0, 0, 1000);
                    return *this 
                        / _control_transfer(_handle, _control_buffer, std::chrono::seconds(10)) 
                        / &WorkerControl::parse_tls_key;
                }
                case ev_arm_result:
                    if(event._ev.unknown!=0)return async_throw(make_error(LIBUSB_ERROR_IO));
                    break;
                case ev_dead_pixel_report:
                {
                    auto bytes=event_bytes(event);
                    if(bytes.size()<4)return async_throw(make_error(LIBUSB_ERROR_IO));
                    uint32_t count=uint32_t(bytes[0])|uint32_t(bytes[1])<<8|uint32_t(bytes[2])<<16|uint32_t(bytes[3])<<24;
                    if(count>560 || bytes.size()!=4+2*count)return async_throw(make_error(LIBUSB_ERROR_IO));
                    std::vector<uint16_t> defects;defects.reserve(count);
                    for(size_t i=0;i<count;++i){uint16_t index=uint16_t(bytes[4+2*i])|uint16_t(bytes[5+2*i])<<8;
                        if(index>=FPC_PIXELS)return async_throw(make_error(LIBUSB_ERROR_IO));defects.push_back(index);}
                    _storage.dead_pixels=std::move(defects);
                    return get_event();
                }
                    break;
                case ev_tls:
                    jinx_log_error() << "unexpected nested TLS event\n";
                    return async_throw(make_error(LIBUSB_ERROR_IO));
                case ev_finger_down:
                    if (_ready && _capture_active && _capture_generation==_storage.capture_generation) {
                        return *this / _put_image(&_image_queue, FPCEvent{FPCEvent::FPP_FingerDown, {}, {}, {}, _capture_generation}) / &WorkerControl::delay_get_image;
                    }
                    break;
                case ev_finger_up:
                    jinx_log_warning() << "tls event ev_finger_up" << std::endl;
                    break;
                case ev_image:
                {
                    if(!_capture_active || _capture_generation!=_storage.capture_generation)return get_event();
                    _capture_active=false;
                    return *this / _put_image(&_image_queue,
                        FPCEvent{FPCEvent::FPP_Image,{},std::move(event._buffers),{},_capture_generation})
                        / &WorkerControl::get_event;
                }
                    break;
                case ev_usb_logs:
                    jinx_log_warning() << "tls event ev_usb_logs" << std::endl;
                    break;
                case ev_tls_key:
                    jinx_log_warning() << "tls event ev_tls_key" << std::endl;
                    break;
                case ev_refresh_sensor:
                    jinx_log_warning() << "tls event ev_refresh_sensor" << std::endl;
                    break;
                default:
                    jinx_log_error() << "unknown event code\n";
                    return async_throw(make_error(LIBUSB_ERROR_IO));
            }

        } else if (event._type == FPCEvent::TLS_Ready) {

            // initialize storage
            std::filesystem::path storage_path{GET_OPTION(std::string, "data-path")};
            if (not std::filesystem::exists(storage_path)) {
                std::filesystem::create_directory(storage_path);
            }
            storage_path /= device_unique_id + "-native.bin";

            _storage.init(storage_path.string(), _tls_key);
            _ready=true;_storage.reader_ready=true;_recovery_attempt=0;
            jinx_log_info()<<"fingerprint sensor ready"<<std::endl;

            _manager->start();
            if(!_device_task)_device_task = task_new<WorkerDevice>(
                &_event_queue, 
                &_image_queue, 
                _manager, 
                &_storage,
                device_unique_id);

            // process pending message
            _manager->get_dbus().dispatch();
            
            libusb_fill_control_setup(_control_buffer,CTRL_HOST_TO_DEVICE,cmd_get_dead_pixel,0,0,0);
            return *this / _control_transfer(_handle,_control_buffer,std::chrono::seconds(10)) / &WorkerControl::get_event;

        } else if (event._type == FPCEvent::FPP_StartSensor) {
            if(!_ready || !_handle || _storage.sleeping)return get_event();
            return start_sensor();

        } else if (event._type == FPCEvent::FPP_StopSensor) {
            _capture_active=false;
            if(!_ready || !_handle)return get_event();
            return stop_sensor();

        } else if (event._type == FPCEvent::FPP_TransportFailed) {
            return notify_operation_failed(event._error);
        } else if(event._type==FPCEvent::FPP_Suspend){
            _suspended=true;_capture_active=false;
            return notify_operation_failed(make_error(LIBUSB_ERROR_INTERRUPTED));
        } else if(event._type==FPCEvent::FPP_Resume){
            if(!_suspended)return get_event();
            _suspended=false;_recovery_attempt=0;return reopen();
        }
        return get_event();
    }

    Async parse_tls_key() {
        int data_length=_control_transfer.get_result();
        unsigned char* data=&_control_buffer[LIBUSB_CONTROL_SETUP_SIZE];
        if(data_length<static_cast<int>(sizeof(fpc_tls_key)))return async_throw(make_error(LIBUSB_ERROR_IO));
        const auto* hdr=reinterpret_cast<const fpc_tls_key*>(data);
        jinx_log_info()<<"wrapped TLS metadata bytes="<<data_length<<" key="<<hdr->key_offset<<":"<<hdr->key_len<<" aad="<<hdr->aad_offset<<":"<<hdr->aad_len<<" signature="<<hdr->sig_offset<<":"<<hdr->sig_len;
        std::vector<unsigned char> tls_key;
        if(!fpc::unwrap_tls_key(data,data_length,tls_key)) {
            jinx_log_error()<<"wrapped TLS key validation failed"<<std::endl;
            return async_throw(make_error(LIBUSB_ERROR_IO));
        }
        _tls_key = std::move(tls_key);
        _pipe->set_tls_key(_tls_key);
        
        libusb_fill_control_setup( _control_buffer, CTRL_HOST_TO_DEVICE, cmd_tls_init, 0x0001, 0, 0);
        return *this 
            / _control_transfer(_handle, _control_buffer, std::chrono::seconds(10)) 
            / &WorkerControl::get_event;        
    }

    Async delay_get_image() {
        if(!_capture_active || _capture_generation!=_storage.capture_generation)return get_event();
        if(std::chrono::steady_clock::now()-_last_image>=std::chrono::milliseconds(200))return get_image();
        return *this / _sleep(std::chrono::milliseconds(200)) / &WorkerControl::get_image;
    }

    Async get_image() {
        if(!_capture_active || _capture_generation!=_storage.capture_generation)return get_event();
        _last_image=std::chrono::steady_clock::now();
        libusb_fill_control_setup( _control_buffer, CTRL_HOST_TO_DEVICE, cmd_get_img, 0x0000, 0x0000, 0);
        
        return *this 
            / _control_transfer(_handle, _control_buffer, std::chrono::seconds(10)) 
            / &WorkerControl::get_event;
    }

    Async start_sensor() {
        _capture_active=true;_capture_generation=_storage.capture_generation;++_arm_token;
        if(std::chrono::steady_clock::now()-_last_arm<std::chrono::milliseconds(100))
            return *this / _sleep(std::chrono::milliseconds(100)) / &WorkerControl::submit_arm;
        return submit_arm();
    }
    Async submit_arm() {
        if(!_capture_active || _capture_generation!=_storage.capture_generation)return get_event();
        _last_arm=std::chrono::steady_clock::now();
        libusb_fill_control_setup(_control_buffer,CTRL_HOST_TO_DEVICE,cmd_arm,2,0,4);
        memcpy(&_control_buffer[LIBUSB_CONTROL_SETUP_SIZE],&_arm_token,4);
        return *this / _control_transfer(_handle,_control_buffer,std::chrono::seconds(10)) / &WorkerControl::get_event;
    }
    Async stop_sensor() {
        _capture_active=false;
        libusb_fill_control_setup(_control_buffer,CTRL_HOST_TO_DEVICE,cmd_abort,1,0,0);
        return *this / _control_transfer(_handle,_control_buffer,std::chrono::seconds(10)) / &WorkerControl::end_enrollment;
    }
    Async end_enrollment() {
        libusb_fill_control_setup(_control_buffer,CTRL_HOST_TO_DEVICE,cmd_end_enrol,0,0,0);
        return *this / _control_transfer(_handle,_control_buffer,std::chrono::seconds(10)) / &WorkerControl::end_session;
    }
    Async end_session() {
        libusb_fill_control_setup(_control_buffer,CTRL_HOST_TO_DEVICE,cmd_fingerprint_sesson_off,0,0,0);
        return *this / _control_transfer(_handle,_control_buffer,std::chrono::seconds(10)) / &WorkerControl::get_event;
    }
    Async get_kpi() {
        // get kpi
        libusb_fill_control_setup( _control_buffer, CTRL_DEVICE_TO_HOST, cmd_get_kpi, 0x0000, 0x0000, 28);
        
        return *this 
            / _control_transfer(_handle, _control_buffer, std::chrono::seconds(10)) 
            / &WorkerControl::parse_kpi;
    }

    Async parse_kpi() {
        unsigned char* data = &_control_buffer[LIBUSB_CONTROL_SETUP_SIZE];
        printf("kpi: \n");
        for (int i = 0 ; i < 28; ++i) {
            printf("%02hhx", data[i]);
        }
        printf("\nkpi end\n");
        fflush(stdout);

        // get dead pixel
        libusb_fill_control_setup( _control_buffer, CTRL_HOST_TO_DEVICE, cmd_get_dead_pixel, 0x0000, 0x0000, 0);
        
        return *this 
            / _control_transfer(_handle, _control_buffer, std::chrono::seconds(10)) 
            / &WorkerControl::get_event;
    }
};

static void start(fingerpp::Manager* manager, fingerpp::USBDeviceInfo* info, USBDeviceHandle&& handle)
{
    manager->get_loop().task_new<WorkerControl>(manager, info, std::move(handle));
}

static void device_attached(fingerpp::Manager* manager, fingerpp::USBDeviceInfo* info, libusb_device* device, libusb_device_descriptor* desc, bool connected)
{
    if (connected) {
        USBDeviceHandle handle{};
        auto ret = libusb_open(device, handle.address());
        if (ret < 0) {
            jinx_log_warning() << "unable to open fingerprint device: "
                               << libusb_error_name(ret) << "; scheduling recovery" << std::endl;
        }
        start(manager, info, std::move(handle));
    }
}

static fingerpp::USBDeviceInfo _device {
    ._vendor = 0x10a5,
    ._product = 0x9201,
    ._callback = device_attached
};

static struct Register {
    Register() {
        fingerpp::Manager::add_usb_device(&_device);
    }
} register_t{};

} // fpc9201
