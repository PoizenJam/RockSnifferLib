using RockSnifferLib.Sniffing;
using System;

namespace RockSnifferLib.Events
{
    public class OnActualSongStartArgs : EventArgs
    {
        public SongDetails song;
        public DateTime timestamp;
    }
}
