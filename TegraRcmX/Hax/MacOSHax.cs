using LibUsbDotNet;
using LibUsbDotNet.LibUsb;
using LibUsbDotNet.Main;
using System;
using System.Linq;

namespace TegramRcmX.Hax
{
    class MacOSHax : HaxBackend
    {
        private IUsbDevice device;
        private UsbEndpointReader reader;
        private UsbEndpointWriter writer;
        public bool FindDevice(ushort VID, ushort PID)
        {
            var LibUsbCtx = new UsbContext();
            LibUsbCtx.SetDebugLevel(LogLevel.Debug);

            var usbDeviceCollection = LibUsbCtx.List();
            device = usbDeviceCollection.FirstOrDefault(d => d.ProductId == PID && d.VendorId == VID);

            return device != null;
        }

        public bool OpenDevice()
        {
            try
            {
                //Open the device
                device.Open();
                //Get the first config number of the interface
                device.ClaimInterface(device.Configs[0].Interfaces[0].Number);
                device.SetAltInterface(0);

                reader = device.OpenEndpointReader(ReadEndpointID.Ep01, 0x10);
                writer = device.OpenEndpointWriter(WriteEndpointID.Ep01);
                return true;
            }
            catch
            {
                return false;
            } 
        }

        public void Read(byte[] buffer)
        {
            reader.Read(buffer, 0, buffer.Length, 100, out _);
        }

        public void WriteSingleBuffer(byte[] buffer)
        {
            if (buffer.Length != 0x1000) return;
            var err = writer.Write(buffer, 0, 0x1000, 100, out _);
        }

        public bool TriggerVulnerability(int length = 0x7000)
        {
            var setup = new UsbSetupPacket
            {
                RequestType = 0x82,
                Request = 0,
                Value = 0,
                Index = 0,
                Length = (short)length
            };

            try
            {
                var buffer = new byte[length];
                var result = device.ControlTransfer(setup, buffer, 0, buffer.Length);

                return true;
            }
            catch
            {
                // which mean we smash success.
                return false;
            }
        }

        public void Close()
        {
            throw new NotImplementedException();
        }
    }
}
