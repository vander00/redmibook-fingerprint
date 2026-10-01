#ifndef FPC_USB_TRANSFER_HPP
#define FPC_USB_TRANSFER_HPP
#include <cstdlib>
#include <cstring>
#include <jinx/usb/usb.hpp>
namespace fpcusb {
using namespace jinx;
using namespace jinx::usb;
// Transfer callbacks own their buffers after cancellation. Closing a handle is
// deferred until every submitted transfer has delivered its completion
// callback.
struct USBPendingHandle {
    size_t transfers{};
    bool closing{};
    int interface_number = -1;
};
inline std::unordered_map<libusb_device_handle *, USBPendingHandle> &pending_usb_handles() {
    static std::unordered_map<libusb_device_handle *, USBPendingHandle> handles;
    return handles;
}
inline void finish_usb_transfer(libusb_device_handle *handle) {
    auto &handles = pending_usb_handles();
    auto found = handles.find(handle);
    if (found == handles.end())
        return;
    if (--found->second.transfers == 0 && !found->second.closing)
        handles.erase(found);

}
inline void defer_usb_close(libusb_device_handle *handle, int interface_number) {
    if (!handle)
        return;
    auto &handles = pending_usb_handles();
    auto found = handles.find(handle);
    if (found == handles.end()) {
        if (interface_number >= 0)
            libusb_release_interface(handle, interface_number);
        libusb_close(handle);
        return;
    }
    found->second.closing = true;
    found->second.interface_number = interface_number;
}
// libusb_close takes libusb's event lock. Never close from the callback:
// callbacks execute while that lock is held. Drain from an event-loop task.
inline bool has_deferred_usb_closes() {
    for(const auto& entry:pending_usb_handles())if(entry.second.closing)return true;
    return false;
}
inline void drain_usb_closes() {
    auto& handles=pending_usb_handles();
    for(auto it=handles.begin();it!=handles.end();) {
        if(!it->second.closing || it->second.transfers){++it;continue;}
        auto* handle=it->first;int interface_number=it->second.interface_number;
        it=handles.erase(it);
        if(interface_number>=0)libusb_release_interface(handle,interface_number);
        libusb_close(handle);
    }
}
class USBTransfer : public jinx::AsyncFunction<int> {
    libusb_transfer *_transfer{};
    unsigned char *_destination{};
    bool _pending{};
    bool _control{};

  public:
    ~USBTransfer() override { release(); }
    JINX_NO_COPY_NO_MOVE(USBTransfer);
    USBTransfer() = default;
    void release() noexcept {
        if (!_transfer)
            return;
        if (_pending) {
            _transfer->user_data = nullptr;
            libusb_cancel_transfer(_transfer);
        } else
            libusb_free_transfer(_transfer);
        _transfer = nullptr;
        _pending = false;
        _destination = nullptr;
    }

  protected:
    void async_finalize() noexcept override {
        release();
        jinx::AsyncFunction<int>::async_finalize();
    }
    bool allocate(size_t size) {
        release();
        _transfer = libusb_alloc_transfer(0);
        if (!_transfer)
            return false;
        _transfer->buffer = static_cast<unsigned char *>(malloc(size ? size : 1));
        if (!_transfer->buffer) {
            libusb_free_transfer(_transfer);
            _transfer = nullptr;
            return false;
        }
        _transfer->flags = LIBUSB_TRANSFER_FREE_BUFFER;
        return true;
    }
    template <typename Rep, typename Period>
    void control(libusb_device_handle *handle, unsigned char *buffer,
                 const std::chrono::duration<Rep, Period> &timeout) {
        const auto *setup = reinterpret_cast<const libusb_control_setup *>(buffer);
        size_t size = LIBUSB_CONTROL_SETUP_SIZE + libusb_le16_to_cpu(setup->wLength);
        if (!allocate(size)) {
            async_throw(make_error(LIBUSB_ERROR_NO_MEM));
            return;
        }
        memcpy(_transfer->buffer, buffer, size);
        _destination = buffer;
        _control = true;
        libusb_fill_control_transfer(
            _transfer, handle, _transfer->buffer, resume, this,
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count());
        async_start(&USBTransfer::submit);
    }
    template <typename Rep, typename Period>
    void bulk(libusb_device_handle *handle, unsigned char endpoint, jinx::SliceRead buffer,
              const std::chrono::duration<Rep, Period> &timeout) {
        if (!allocate(buffer.size())) {
            async_throw(make_error(LIBUSB_ERROR_NO_MEM));
            return;
        }
        memcpy(_transfer->buffer, buffer.data(), buffer.size());
        _destination = static_cast<unsigned char *>(buffer.data());
        _control = false;
        libusb_fill_bulk_transfer(
            _transfer, handle, endpoint, _transfer->buffer, buffer.size(), resume, this,
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count());
        async_start(&USBTransfer::submit);
    }
    jinx::Async submit() {
        auto& handles=pending_usb_handles();
        // Allocate tracking before submission: an allocation failure must
        // never leave an in-flight transfer that appears safe to free.
        auto entry=handles.try_emplace(_transfer->dev_handle).first;
        if(entry->second.closing)
            return async_throw(make_error(LIBUSB_ERROR_NO_DEVICE));
        int result = libusb_submit_transfer(_transfer);
        if (result < 0) {
            if(!entry->second.transfers)handles.erase(entry);
            return async_throw(make_error(static_cast<libusb_error>(result)));
        }
        ++entry->second.transfers;
        _pending = true;
        async_start(&USBTransfer::completed);
        return async_suspend();
    }
    jinx::Async completed() {
        if (_transfer->status != LIBUSB_TRANSFER_COMPLETED)
            return async_throw(make_error(_transfer->status));
        size_t offset = _control ? LIBUSB_CONTROL_SETUP_SIZE : 0;
        memcpy(_destination + offset, _transfer->buffer + offset, _transfer->actual_length);
        emplace_result(_transfer->actual_length);
        return async_return();
    }
    static void resume(libusb_transfer *transfer) {
        auto *self = static_cast<USBTransfer *>(transfer->user_data);
        finish_usb_transfer(transfer->dev_handle);
        if (!self) {
            libusb_free_transfer(transfer);
            return;
        }
        self->_pending = false;
        self->async_resume() >> JINX_IGNORE_RESULT;
    }
};
class USBControlTransfer : public USBTransfer {
  public:
    template <typename Rep, typename Period>
    USBControlTransfer &operator()(libusb_device_handle *handle, unsigned char *buffer,
                                   const std::chrono::duration<Rep, Period> &timeout) {
        control(handle, buffer, timeout);
        return *this;
    }
};
class USBBulkTransfer : public USBTransfer {
  public:
    template <typename Rep, typename Period>
    USBBulkTransfer &operator()(libusb_device_handle *handle, unsigned char endpoint,
                                jinx::SliceRead buffer,
                                const std::chrono::duration<Rep, Period> &timeout) {
        bulk(handle, endpoint, buffer, timeout);
        return *this;
    }
};

} // namespace fpcusb
#endif
