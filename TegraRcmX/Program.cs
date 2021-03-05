using System;
using System.IO;

namespace TegramRcmX
{
    class Program
    {
        static void Main(string[] args)
        {
            var device = new RcmDevice();

            try
            {
                var ret = device.InitDevice();

                if (ret != "success")
                {
                    throw new Exception($"Error success: {ret}");
                }
            }
            catch(Exception e)
            {
                Console.WriteLine($"Error: {e}");
                return;
            }
            
            Console.WriteLine($"Device ID: {device.GetDeviceID()}");

            Console.WriteLine("Writing payload...");

            var path = @"D:\repositories\rcmlaucher\hekate_ctcaer_5.5.4.bin";
            device.SendPayload(path);

            Console.WriteLine("Smashing...");
            Console.WriteLine(!device.TriggerControlledMemcpy()
                   ? "Successfully smashed device!"
                   : "it seems your Switch isn't vulnerable.");
            
            Console.WriteLine("Launch complete!");
        }
    }
}
