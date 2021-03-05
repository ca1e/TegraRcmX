
namespace TegramRcmX.Hax
{
    interface HaxBackend
    {
        bool FindDevice(ushort VID, ushort PID);

        bool OpenDevice();

        void Read(byte[] buffer);

        void WriteSingleBuffer(byte[] buffer);  // length always 0x1000

        bool TriggerVulnerability(int length = 0x7000);

        void Close();
    }
}
