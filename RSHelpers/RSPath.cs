namespace RockSnifferLib.RSHelpers
{
    /// <summary>
    /// The user's currently-selected Path (arrangement type) at the menu level.
    /// Values match the raw byte read from memory (see
    /// MemoryOffsets.GetCurrentPathPointer), so the original byte is recoverable
    /// by casting if ever needed.
    /// </summary>
    public enum RSPath
    {
        /// <summary>Byte didn't match a known Path value, or the read failed.</summary>
        Unknown = 0x00,
        Lead = 0x01,
        Rhythm = 0x02,
        Bass = 0x04
    }
}
