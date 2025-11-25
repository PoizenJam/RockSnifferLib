using System;

namespace RockSnifferLib.Logging
{
    public class EventLoggedArgs : EventArgs
    {
        public DateTime Timestamp { get; set; }
        public string Message { get; set; }
    }
}
