using RockSnifferLib.Sniffing;
using System;

namespace RockSnifferLib.Events
{
    public class OnActualSongEndArgs : EventArgs
    {
        public SongDetails song;
        public DateTime timestamp;
        public bool completed;
        public bool paused;
    }
}
