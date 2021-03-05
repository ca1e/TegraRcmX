using libusbK;
using System;

namespace TegramRcmX.Hax
{
    class WindowsHax : HaxBackend
    {
        UsbK device;
        KLST_DEVINFO_HANDLE deviceInfo;
        public bool FindDevice(ushort VID, ushort PID)
        {
            var patternMatch = new KLST_PATTERN_MATCH { DeviceID = @"USB\VID_0955&PID_7321" };
            var deviceList = new LstK(0, ref patternMatch);
            return deviceList.MoveNext(out deviceInfo);
        }

        public bool OpenDevice()
        {
            try
            {
                device = new UsbK(deviceInfo);
                device.SetAltInterface(0, false, 0);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Read(byte[] buffer)
        {
            device.ReadPipe(0x81, buffer, buffer.Length, out _, IntPtr.Zero);
        }

        public void WriteSingleBuffer(byte[] buffer)
        {
            if (buffer.Length != 0x1000) return;
            var b = device.WritePipe(1, buffer, 0x1000, out _, IntPtr.Zero);
        }

        public bool TriggerVulnerability(int length = 0x7000)
        {
            var setup = new WINUSB_SETUP_PACKET
            {
                RequestType = 0x82,
                Request = 0,
                Value = 0,
                Index = 0,
                Length = (ushort)length
            };

            var buffer = new byte[length];
            var result = device.ControlTransfer(setup, buffer, buffer.Length, out var b, IntPtr.Zero);
            
            // we need false
            return result;
        }

        public void Close()
        {
            throw new NotImplementedException();
        }
    }
}
