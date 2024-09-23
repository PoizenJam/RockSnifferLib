using Org.BouncyCastle.Asn1.Mozilla;
using Rocksmith2014PsarcLib.Psarc.Models.Json;
using System;
using System.Collections.Generic;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace RockSnifferLib.Sniffing
{
    [Serializable]
    public class ArrangementTuning
    {

        private static readonly Dictionary<string, ArrangementTuning> _TuningNames = new Dictionary<string, ArrangementTuning>()
        {
            ["3G-E Standard"] = new ArrangementTuning(false, 12, 12, 12, 12, 12, 12, -999, -999),
            ["2G-Eb Standard"] = new ArrangementTuning(false, 11, 11, 11, 11, 11, 11, -999, -999),
            ["2G-D Standard"] = new ArrangementTuning(false, 10, 10, 10, 10, 10, 10, -999, -999),
            ["2G-C# Standard"] = new ArrangementTuning(false, 9, 9, 9, 9, 9, 9, -999, -999),
            ["2G-C Standard"] = new ArrangementTuning(false, 8, 8, 8, 8, 8, 8, -999, -999),
            ["2G-B Standard"] = new ArrangementTuning(false, 7, 7, 7, 7, 7, 7, -999, -999),
            ["2G-Bb Standard"] = new ArrangementTuning(false, 6, 6, 6, 6, 6, 6, -999, -999),
            ["2G-A Standard"] = new ArrangementTuning(false, 5, 5, 5, 5, 5, 5, -999, -999),
            ["2G-Ab Standard"] = new ArrangementTuning(false, 4, 4, 4, 4, 4, 4, -999, -999),
            ["2G-G Standard"] = new ArrangementTuning(false, 3, 3, 3, 3, 3, 3, -999, -999),
            ["2G-F# Standard"] = new ArrangementTuning(false, 2, 2, 2, 2, 2, 2, -999, -999),
            ["2G-F Standard"] = new ArrangementTuning(false, 1, 1, 1, 1, 1, 1, -999, -999),
            ["2G-E Standard"] = new ArrangementTuning(false, 0, 0, 0, 0, 0, 0, -999, -999),
            ["1G-Eb Standard"] = new ArrangementTuning(false, -1, -1, -1, -1, -1, -1, -999, -999),
            ["1G-D Standard"] = new ArrangementTuning(false, -2, -2, -2, -2, -2, -2, -999, -999),
            ["1G-C# Standard"] = new ArrangementTuning(false, -3, -3, -3, -3, -3, -3, -999, -999),
            ["1G-C Standard"] = new ArrangementTuning(false, -4, -4, -4, -4, -4, -4, -999, -999),
            ["1G-B Standard"] = new ArrangementTuning(false, -5, -5, -5, -5, -5, -5, -999, -999),
            ["1G-Bb Standard"] = new ArrangementTuning(false, -6, -6, -6, -6, -6, -6, -999, -999),
            ["1G-A Standard"] = new ArrangementTuning(false, -7, -7, -7, -7, -7, -7, -999, -999),
            ["1G-Ab Standard"] = new ArrangementTuning(false, -8, -8, -8, -8, -8, -8, -999, -999),
            ["1G-G Standard"] = new ArrangementTuning(false, -9, -9, -9, -9, -9, -9, -999, -999),
            ["1G-F# Standard"] = new ArrangementTuning(false, -10, -10, -10, -10, -10, -10, -999, -999),
            ["1G-F Standard"] = new ArrangementTuning(false, -11, -11, -11, -11, -11, -11, -999, -999),
            ["1G-E Standard"] = new ArrangementTuning(false, -12, -12, -12, -12, -12, -12, -999, -999),

            ["3B-E Standard"] = new ArrangementTuning(true, 12, 12, 12, 12, 12, 12, -999, -999),
            ["2B-Eb Standard"] = new ArrangementTuning(true, 11, 11, 11, 11, 11, 11, -999, -999),
            ["2B-D Standard"] = new ArrangementTuning(true, 10, 10, 10, 10, 10, 10, -999, -999),
            ["2B-C# Standard"] = new ArrangementTuning(true, 9, 9, 9, 9, 9, 9, -999, -999),
            ["2B-C Standard"] = new ArrangementTuning(true, 8, 8, 8, 8, 8, 8, -999, -999),
            ["2B-B Standard"] = new ArrangementTuning(true, 7, 7, 7, 7, 7, 7, -999, -999),
            ["2B-Bb Standard"] = new ArrangementTuning(true, 6, 6, 6, 6, 6, 6, -999, -999),
            ["2B-A Standard"] = new ArrangementTuning(true, 5, 5, 5, 5, 5, 5, -999, -999),
            ["2B-Ab Standard"] = new ArrangementTuning(true, 4, 4, 4, 4, 4, 4, -999, -999),
            ["2B-G Standard"] = new ArrangementTuning(true, 3, 3, 3, 3, 3, 3, -999, -999),
            ["2B-F# Standard"] = new ArrangementTuning(true, 2, 2, 2, 2, 2, 2, -999, -999),
            ["2B-F Standard"] = new ArrangementTuning(true, 1, 1, 1, 1, 1, 1, -999, -999),
            ["2B-E Standard"] = new ArrangementTuning(true, 0, 0, 0, 0, 0, 0, -999, -999),
            ["1B-Eb Standard"] = new ArrangementTuning(true, -1, -1, -1, -1, -1, -1, -999, -999),
            ["1B-D Standard"] = new ArrangementTuning(true, -2, -2, -2, -2, -2, -2, -999, -999),
            ["1B-C# Standard"] = new ArrangementTuning(true, -3, -3, -3, -3, -3, -3, -999, -999),
            ["1B-C Standard"] = new ArrangementTuning(true, -4, -4, -4, -4, -4, -4, -999, -999),
            ["1B-B Standard"] = new ArrangementTuning(true, -5, -5, -5, -5, -5, -5, -999, -999),
            ["1B-Bb Standard"] = new ArrangementTuning(true, -6, -6, -6, -6, -6, -6, -999, -999),
            ["1B-A Standard"] = new ArrangementTuning(true, -7, -7, -7, -7, -7, -7, -999, -999),
            ["1B-Ab Standard"] = new ArrangementTuning(true, -8, -8, -8, -8, -8, -8, -999, -999),
            ["1B-G Standard"] = new ArrangementTuning(true, -9, -9, -9, -9, -9, -9, -999, -999),
            ["1B-F# Standard"] = new ArrangementTuning(true, -10, -10, -10, -10, -10, -10, -999, -999),
            ["1B-F Standard"] = new ArrangementTuning(true, -11, -11, -11, -11, -11, -11, -999, -999),
            ["1B-E Standard"] = new ArrangementTuning(true, -12, -12, -12, -12, -12, -12, -999, -999),

            ["3Bb-E Standard"] = new ArrangementTuning(true, 12, 12, 12, 12, 0, 0, -999, -999),
            ["2Bb-Eb Standard"] = new ArrangementTuning(true, 11, 11, 11, 11, 0, 0, -999, -999),
            ["2Bb-D Standard"] = new ArrangementTuning(true, 10, 10, 10, 10, 0, 0, -999, -999),
            ["2Bb-C# Standard"] = new ArrangementTuning(true, 9, 9, 9, 9, 0, 0, -999, -999),
            ["2Bb-C Standard"] = new ArrangementTuning(true, 8, 8, 8, 8, 0, 0, -999, -999),
            ["2Bb-B Standard"] = new ArrangementTuning(true, 7, 7, 7, 7, 0, 0, -999, -999),
            ["2Bb-Bb Standard"] = new ArrangementTuning(true, 6, 6, 6, 6, 0, 0, -999, -999),
            ["2Bb-A Standard"] = new ArrangementTuning(true, 5, 5, 5, 5, 0, 0, -999, -999),
            ["2Bb-Ab Standard"] = new ArrangementTuning(true, 4, 4, 4, 4, 0, 0, -999, -999),
            ["2Bb-G Standard"] = new ArrangementTuning(true, 3, 3, 3, 3, 0, 0, -999, -999),
            ["2Bb-F# Standard"] = new ArrangementTuning(true, 2, 2, 2, 2, 0, 0, -999, -999),
            ["2Bb-F Standard"] = new ArrangementTuning(true, 1, 1, 1, 1, 0, 0, -999, -999),
            ["1Bb-Eb Standard"] = new ArrangementTuning(true, -1, -1, -1, -1, 0, 0, -999, -999),
            ["1Bb-D Standard"] = new ArrangementTuning(true, -2, -2, -2, -2, 0, 0, -999, -999),
            ["1Bb-C# Standard"] = new ArrangementTuning(true, -3, -3, -3, -3, 0, 0, -999, -999),
            ["1Bb-C Standard"] = new ArrangementTuning(true, -4, -4, -4, -4, 0, 0, -999, -999),
            ["1Bb-B Standard"] = new ArrangementTuning(true, -5, -5, -5, -5, 0, 0, -999, -999),
            ["1Bb-Bb Standard"] = new ArrangementTuning(true, -6, -6, -6, -6, 0, 0, -999, -999),
            ["1Bb-A Standard"] = new ArrangementTuning(true, -7, -7, -7, -7, 0, 0, -999, -999),
            ["1Bb-Ab Standard"] = new ArrangementTuning(true, -8, -8, -8, -8, 0, 0, -999, -999),
            ["1Bb-G Standard"] = new ArrangementTuning(true, -9, -9, -9, -9, 0, 0, -999, -999),
            ["1Bb-F# Standard"] = new ArrangementTuning(true, -10, -10, -10, -10, 0, 0, -999, -999),
            ["1Bb-F Standard"] = new ArrangementTuning(true, -11, -11, -11, -11, 0, 0, -999, -999),
            ["1Bb-E Standard"] = new ArrangementTuning(true, -12, -12, -12, -12, 0, 0, -999, -999),

            ["3G-F# Drop E"] = new ArrangementTuning(false, 12, 14, 14, 14, 14, 14, -999, -999),
            ["3G-F Drop Eb"] = new ArrangementTuning(false, 11, 13, 13, 13, 13, 13, -999, -999),
            ["3G-Drop D"] = new ArrangementTuning(false, 10, 12, 12, 12, 12, 12, -999, -999),
            ["2G-Eb Drop Db"] = new ArrangementTuning(false, 9, 11, 11, 11, 11, 11, -999, -999),
            ["2G-D Drop C"] = new ArrangementTuning(false, 8, 10, 10, 10, 10, 10, -999, -999),
            ["2G-C# Drop B"] = new ArrangementTuning(false, 7, 9, 9, 9, 9, 9, -999, -999),
            ["2G-C Drop Bb"] = new ArrangementTuning(false, 6, 8, 8, 8, 8, 8, -999, -999),
            ["2G-B Drop A"] = new ArrangementTuning(false, 5, 7, 7, 7, 7, 7, -999, -999),
            ["2G-Bb Drop Ab"] = new ArrangementTuning(false, 4, 6, 6, 6, 6, 6, -999, -999),
            ["2G-A Drop G"] = new ArrangementTuning(false, 3, 5, 5, 5, 5, 5, -999, -999),
            ["2G-Ab Drop F#"] = new ArrangementTuning(false, 2, 4, 4, 4, 4, 4, -999, -999),
            ["2G-G Drop F"] = new ArrangementTuning(false, 1, 3, 3, 3, 3, 3, -999, -999),
            ["2G-F# Drop E"] = new ArrangementTuning(false, 0, 2, 2, 2, 2, 2, -999, -999),
            ["2G-F Drop Eb"] = new ArrangementTuning(false, -1, 1, 1, 1, 1, 1, -999, -999),
            ["2G-Drop D"] = new ArrangementTuning(false, -2, 0, 0, 0, 0, 0, -999, -999),
            ["1G-Eb Drop Db"] = new ArrangementTuning(false, -3, -1, -1, -1, -1, -1, -999, -999),
            ["1G-D Drop C"] = new ArrangementTuning(false, -4, -2, -2, -2, -2, -2, -999, -999),
            ["1G-C# Drop B"] = new ArrangementTuning(false, -5, -3, -3, -3, -3, -3, -999, -999),
            ["1G-C Drop Bb"] = new ArrangementTuning(false, -6, -4, -4, -4, -4, -4, -999, -999),
            ["1G-B Drop A"] = new ArrangementTuning(false, -7, -5, -5, -5, -5, -5, -999, -999),
            ["1G-Bb Drop Ab"] = new ArrangementTuning(false, -8, -6, -6, -6, -6, -6, -999, -999),
            ["1G-A Drop G"] = new ArrangementTuning(false, -9, -7, -7, -7, -7, -7, -999, -999),
            ["1G-Ab Drop F#"] = new ArrangementTuning(false, -10, -8, -8, -8, -8, -8, -999, -999),
            ["1G-G Drop F"] = new ArrangementTuning(false, -11, -9, -9, -9, -9, -9, -999, -999),
            ["1G-F# Drop E"] = new ArrangementTuning(false, -12, -10, -10, -10, -10, -10, -999, -999),
            ["1G-F Drop Eb"] = new ArrangementTuning(false, -13, -11, -11, -11, -11, -11, -999, -999),
            ["1G-Drop D"] = new ArrangementTuning(false, -14, -12, -12, -12, -12, -12, -999, -999),

            ["3B-F# Drop E"] = new ArrangementTuning(true, 12, 14, 14, 14, 14, 14, -999, -999),
            ["3B-F Drop Eb"] = new ArrangementTuning(true, 11, 13, 13, 13, 13, 13, -999, -999),
            ["3B-Drop D"] = new ArrangementTuning(true, 10, 12, 12, 12, 12, 12, -999, -999),
            ["2B-Eb Drop Db"] = new ArrangementTuning(true, 9, 11, 11, 11, 11, 11, -999, -999),
            ["2B-D Drop C"] = new ArrangementTuning(true, 8, 10, 10, 10, 10, 10, -999, -999),
            ["2B-C# Drop B"] = new ArrangementTuning(true, 7, 9, 9, 9, 9, 9, -999, -999),
            ["2B-C Drop Bb"] = new ArrangementTuning(true, 6, 8, 8, 8, 8, 8, -999, -999),
            ["2B-B Drop A"] = new ArrangementTuning(true, 5, 7, 7, 7, 7, 7, -999, -999),
            ["2B-Bb Drop Ab"] = new ArrangementTuning(true, 4, 6, 6, 6, 6, 6, -999, -999),
            ["2B-A Drop G"] = new ArrangementTuning(true, 3, 5, 5, 5, 5, 5, -999, -999),
            ["2B-Ab Drop F#"] = new ArrangementTuning(true, 2, 4, 4, 4, 4, 4, -999, -999),
            ["2B-G Drop F"] = new ArrangementTuning(true, 1, 3, 3, 3, 3, 3, -999, -999),
            ["2B-F# Drop E"] = new ArrangementTuning(true, 0, 2, 2, 2, 2, 2, -999, -999),
            ["2B-F Drop Eb"] = new ArrangementTuning(true, -1, 1, 1, 1, 1, 1, -999, -999),
            ["2B-Drop D"] = new ArrangementTuning(true, -2, 0, 0, 0, 0, 0, -999, -999),
            ["1B-Eb Drop Db"] = new ArrangementTuning(true, -3, -1, -1, -1, -1, -1, -999, -999),
            ["1B-D Drop C"] = new ArrangementTuning(true, -4, -2, -2, -2, -2, -2, -999, -999),
            ["1B-C# Drop B"] = new ArrangementTuning(true, -5, -3, -3, -3, -3, -3, -999, -999),
            ["1B-C Drop Bb"] = new ArrangementTuning(true, -6, -4, -4, -4, -4, -4, -999, -999),
            ["1B-B Drop A"] = new ArrangementTuning(true, -7, -5, -5, -5, -5, -5, -999, -999),
            ["1B-Bb Drop Ab"] = new ArrangementTuning(true, -8, -6, -6, -6, -6, -6, -999, -999),
            ["1B-A Drop G"] = new ArrangementTuning(true, -9, -7, -7, -7, -7, -7, -999, -999),
            ["1B-Ab Drop F#"] = new ArrangementTuning(true, -10, -8, -8, -8, -8, -8, -999, -999),
            ["1B-G Drop F"] = new ArrangementTuning(true, -11, -9, -9, -9, -9, -9, -999, -999),
            ["1B-F# Drop E"] = new ArrangementTuning(true, -12, -10, -10, -10, -10, -10, -999, -999),
            ["1B-F Drop Eb"] = new ArrangementTuning(true, -13, -11, -11, -11, -11, -11, -999, -999),
            ["1B-Drop D"] = new ArrangementTuning(true, -14, -12, -12, -12, -12, -12, -999, -999),

            ["3Bb-F# Drop E"] = new ArrangementTuning(true, 12, 14, 14, 14, 0, 0, -999, -999),
            ["3Bb-F Drop Eb"] = new ArrangementTuning(true, 11, 13, 13, 13, 0, 0, -999, -999),
            ["3Bb-Drop D"] = new ArrangementTuning(true, 10, 12, 12, 12, 0, 0, -999, -999),
            ["2Bb-Eb Drop Db"] = new ArrangementTuning(true, 9, 11, 11, 11, 0, 0, -999, -999),
            ["2Bb-D Drop C"] = new ArrangementTuning(true, 8, 10, 10, 10, 0, 0, -999, -999),
            ["2Bb-C# Drop B"] = new ArrangementTuning(true, 7, 9, 9, 9, 0, 0, -999, -999),
            ["2Bb-C Drop Bb"] = new ArrangementTuning(true, 6, 8, 8, 8, 0, 0, -999, -999),
            ["2Bb-B Drop A"] = new ArrangementTuning(true, 5, 7, 7, 7, 0, 0, -999, -999),
            ["2Bb-Bb Drop Ab"] = new ArrangementTuning(true, 4, 6, 6, 6, 0, 0, -999, -999),
            ["2Bb-A Drop G"] = new ArrangementTuning(true, 3, 5, 5, 5, 0, 0, -999, -999),
            ["2Bb-Ab Drop F#"] = new ArrangementTuning(true, 2, 4, 4, 4, 0, 0, -999, -999),
            ["2Bb-G Drop F"] = new ArrangementTuning(true, 1, 3, 3, 3, 0, 0, -999, -999),
            ["2Bb-F# Drop E"] = new ArrangementTuning(true, 0, 2, 2, 2, 0, 0, -999, -999),
            ["2Bb-F Drop Eb"] = new ArrangementTuning(true, -1, 1, 1, 1, 0, 0, -999, -999),
            ["2Bb-Drop D"] = new ArrangementTuning(true, -2, 0, 0, 0, 0, 0, -999, -999),
            ["1Bb-Eb Drop Db"] = new ArrangementTuning(true, -3, -1, -1, -1, 0, 0, -999, -999),
            ["1Bb-D Drop C"] = new ArrangementTuning(true, -4, -2, -2, -2, 0, 0, -999, -999),
            ["1Bb-C# Drop B"] = new ArrangementTuning(true, -5, -3, -3, -3, 0, 0, -999, -999),
            ["1Bb-C Drop Bb"] = new ArrangementTuning(true, -6, -4, -4, -4, 0, 0, -999, -999),
            ["1Bb-B Drop A"] = new ArrangementTuning(true, -7, -5, -5, -5, 0, 0, -999, -999),
            ["1Bb-Bb Drop Ab"] = new ArrangementTuning(true, -8, -6, -6, -6, 0, 0, -999, -999),
            ["1Bb-A Drop G"] = new ArrangementTuning(true, -9, -7, -7, -7, 0, 0, -999, -999),
            ["1Bb-Ab Drop F#"] = new ArrangementTuning(true, -10, -8, -8, -8, 0, 0, -999, -999),
            ["1Bb-G Drop F"] = new ArrangementTuning(true, -11, -9, -9, -9, 0, 0, -999, -999),
            ["1Bb-F# Drop E"] = new ArrangementTuning(true, -12, -10, -10, -10, 0, 0, -999, -999),
            ["1Bb-F Drop Eb"] = new ArrangementTuning(true, -13, -11, -11, -11, 0, 0, -999, -999),
            ["1Bb-Drop D"] = new ArrangementTuning(true, -14, -12, -12, -12, 0, 0, -999, -999),

            ["1G-Open A"] = new ArrangementTuning(false,0, 0, 2, 2, 2, 0, -999, -999),
            ["1G-Open B"] = new ArrangementTuning(false,-5, -3, -3, -1, 0, -1, -999, -999),
            ["1G-Open C"] = new ArrangementTuning(false,-4, -2, -2, 0, 1, 0, -999, -999),
            ["1G-Open D"] = new ArrangementTuning(false,-2, 0, 0, -1, -2, -2, -999, -999),
            ["1G-Open E"] = new ArrangementTuning(false,0, 2, 2, 1, 0, 0, -999, -999),
            ["1G-Open F"] = new ArrangementTuning(false,-4, -4, -2, -2, -2, 1, -999, -999),
            ["1G-Open G"] = new ArrangementTuning(false,-2, -2, 0, 0, 0, -2, -999, -999),

            ["1B-Open A"] = new ArrangementTuning(true,0, 0, 2, 2, 2, 0, -999, -999),
            ["1B-Open B"] = new ArrangementTuning(true,-5, -3, -3, -1, 0, -1, -999, -999),
            ["1B-Open C"] = new ArrangementTuning(true, -4, -2, -2, 0, 1, 0, -999, -999),
            ["1B-Open D"] = new ArrangementTuning(true,-2, 0, 0, -1, -2, -2, -999, -999),
            ["1B-Open E"] = new ArrangementTuning(true,0, 2, 2, 1, 0, 0, -999, -999),
            ["1B-Open F"] = new ArrangementTuning(true,-4, -4, -2, -2, -2, 1, -999, -999),
            ["1B-Open G"] = new ArrangementTuning(true,-2, -2, 0, 0, 0, -2, -999, -999),

            ["1G-DADGAD"] = new ArrangementTuning(false,-2, 0, 0, 0, -2, -2, -999, -999),
            ["1G-Minor Third"] = new ArrangementTuning(false,-4, -6, -8, -10, -11, -13, -999, -999),
            ["1G-Major Third"] = new ArrangementTuning(false,-8, -9, -10, -11, -11, -12, -999, -999),
            ["1G-Fourths"] = new ArrangementTuning(false,0, 0, 0, 0, 1, 1, -999, -999),
            ["1G-Aug Fourths"] = new ArrangementTuning(false,-4, -3, -2, -1, 1, 2, -999, -999),
            ["1G-Fifths"] = new ArrangementTuning(false,-4, -2, 0, 2, 5, 7, -999, -999),
            ["1G-Double Drop D"] = new ArrangementTuning(false,-2, 0, 0, 0, 0, -2, -999, -999),
            ["1G-Nick Drake"] = new ArrangementTuning(false,-4, -2, -2, -2, 1, 0, -999, -999),
            ["1G-C6 Modal"] = new ArrangementTuning(false,-4, 0, -2, 0, 1, 0, -999, -999),

            ["1B-DADGAD"] = new ArrangementTuning(true, -2, 0, 0, 0, -2, -2, -999, -999),
            ["1B-Minor Third"] = new ArrangementTuning(true, -4, -6, -8, -10, -11, -13, -999, -999),
            ["1B-Major Third"] = new ArrangementTuning(true, -8, -9, -10, -11, -11, -12, -999, -999),
            ["1B-Fourths"] = new ArrangementTuning(true, 0, 0, 0, 0, 1, 1, -999, -999),
            ["1B-Aug Fourths"] = new ArrangementTuning(true, -4, -3, -2, -1, 1, 2, -999, -999),
            ["1B-Fifths"] = new ArrangementTuning(true, -4, -2, 0, 2, 5, 7, -999, -999),
            ["1B-Double Drop D"] = new ArrangementTuning(true, -2, 0, 0, 0, 0, -2, -999, -999),
            ["1B-Nick Drake"] = new ArrangementTuning(true, -4, -2, -2, -2, 1, 0, -999, -999),
            ["1B-C6 Modal"] = new ArrangementTuning(true, -4, 0, -2, 0, 1, 0, -999, -999),
        };
        private string GetTuningFallback(int[] offsets)
        {
            // Standard tuning notes from the 6th to 1st string: E, A, D, G, B, e
            List<string> standardTuning = new List<string> { "E", "A", "D", "G", "B", "e" };

            // Chromatic scale with both sharps and flats
            List<string> notes = new List<string>
            {
                "A", "Bb", "B", "C", "Db", "D", "Eb", "E", "F", "F#", "G", "Ab"
            };

            // Enharmonic equivalents (e.g., A# == Bb, C# == Db, etc.)
            Dictionary<string, string> enharmonics = new Dictionary<string, string>
            {
                { "Bb", "A#" }, { "Db", "C#" }, { "Eb", "D#" }, { "F#", "Gb" }, { "Ab", "G#" }
            };

            List<string> tuningResult = new List<string>();

            // Set default string count for tuning name
            int string_count = 6;

            // Check if Tuning is on BASS; trim to 4 string name if so
            if (Bass) { string_count = 6; } else { string_count = 4; }

            for (int i = 0; i < string_count; i++)
            {
                if (offsets[i] == -999)  // Skip disabled strings
                    continue;

                // Get the index of the note in the chromatic scale based on the standard tuning
                int noteIndex = notes.IndexOf(standardTuning[i].ToUpper());
                int newNoteIndex = (noteIndex + offsets[i]) % 12;
                if (newNoteIndex < 0)
                    newNoteIndex += 12;  // Wrap around negative values

                // Get the new note
                string newNote = notes[newNoteIndex];

                // Add the note to the result list
                tuningResult.Add(newNote);
            }

            // Check for duplicates and use enharmonic equivalents if necessary
            for (int i = 0; i < tuningResult.Count; i++)
            {
                if (tuningResult.Count(x => x == tuningResult[i]) > 1 && enharmonics.ContainsKey(tuningResult[i]))
                {
                    // Replace the duplicate with its enharmonic equivalent
                    tuningResult[i] = enharmonics[tuningResult[i]];
                }
            }

            // Join the result into a single string (e.g., "DADGBE")
            return string.Join("", tuningResult);
        }

        public string TuningName
        {
            get
            {
                string name = "Custom Tuning";

                //Find the tuning name in the dictionary
                KeyValuePair<string, ArrangementTuning> tuningNamePair = _TuningNames.FirstOrDefault(kvp => kvp.Value.Equals(this));
                if (!tuningNamePair.Equals(default(KeyValuePair<string, ArrangementTuning>))) name = tuningNamePair.Key;
                name = name.Replace("1G-", "").Replace("2G-", "").Replace("3G-", "").Replace("1B-", "").Replace("2B-", "").Replace("3B-", "").Replace("1Bb-", "").Replace("2Bb-", "").Replace("3Bb-", "");

                if (name == "Custom Tuning")
                {
                    name = GetTuningFallback(new int[] { String0, String1, String2, String3, String4, String5 });
                }

                //Calculate estimated hz offset from cents offset, if nonzero
                if (CentsOffset != 0)
                {
                    name = $"{name} A{Math.Floor(440d * Math.Pow(2d, CentsOffset / 1200d))}";
                }
                

                //Add capo fret
                if (CapoFret != 0)
                {
                    name = $"{name} (Capo Fret {CapoFret})";
                }

                return name;
            }
        }

        /// <summary>
        /// Invalid tuning
        /// </summary>
        public ArrangementTuning()
        {
            String0 = -999;
            String1 = -999;
            String2 = -999;
            String3 = -999;
            String4 = -999;
            String5 = -999;
            CentsOffset = -999;
            CapoFret = -999;
            Bass = false;
        }

        public ArrangementTuning(bool isBass, int string0, int string1, int string2, int string3, int string4, int string5, int centsOffset, int capoFret)
        {
            String0 = string0;
            String1 = string1;
            String2 = string2;
            String3 = string3;
            String4 = string4;
            String5 = string5;
            CentsOffset = centsOffset;
            CapoFret = capoFret;
            Bass = isBass;
        }

        public ArrangementTuning(bool isBass, SongArrangement.ArrangementAttributes.ArrangementTuning tuning, int centsOffset, int capoFret)
        {
            String0 = tuning.String0;
            String1 = tuning.String1;
            String2 = tuning.String2;
            String3 = tuning.String3;
            String4 = tuning.String4;
            String5 = tuning.String5;
            CentsOffset = centsOffset;
            CapoFret = capoFret;
            Bass = isBass;
        }

        //public string Path;
        public int CentsOffset;
        public int CapoFret;
        public int String0;
        public int String1;
        public int String2;
        public int String3;
        public int String4;
        public int String5;
        public bool Bass;

        /// <summary>
        /// Check if two tunings are equal, capo fret and cents offset are ignored
        /// </summary>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj is ArrangementTuning)
            {
                var t = obj as ArrangementTuning;
                return t.String0 == String0 &&
                    t.String1 == String1 &&
                    t.String2 == String2 &&
                    t.String3 == String3 &&
                    t.String4 == String4 &&
                    t.String5 == String5;
            }

            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}
