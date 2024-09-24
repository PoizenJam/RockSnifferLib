using Org.BouncyCastle.Asn1.Mozilla;
using Org.BouncyCastle.Asn1.Sec;
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
        private static readonly Dictionary<ArrangementTuning, string> _TuningNames = new Dictionary<ArrangementTuning, string>()
        {
            [new ArrangementTuning(12, 12, 12, 12, 12, 12, -999, -999, false)] = "E Standard",
            [new ArrangementTuning(11, 11, 11, 11, 11, 11, -999, -999, false)] = "Eb Standard",
            [new ArrangementTuning(10, 10, 10, 10, 10, 10, -999, -999, false)] = "D Standard",
            [new ArrangementTuning(9, 9, 9, 9, 9, 9, -999, -999, false)] = "C# Standard",
            [new ArrangementTuning(8, 8, 8, 8, 8, 8, -999, -999, false)] = "C Standard",
            [new ArrangementTuning(7, 7, 7, 7, 7, 7, -999, -999, false)] = "B Standard",
            [new ArrangementTuning(6, 6, 6, 6, 6, 6, -999, -999, false)] = "Bb Standard",
            [new ArrangementTuning(5, 5, 5, 5, 5, 5, -999, -999, false)] = "A Standard",
            [new ArrangementTuning(4, 4, 4, 4, 4, 4, -999, -999, false)] = "Ab Standard",
            [new ArrangementTuning(3, 3, 3, 3, 3, 3, -999, -999, false)] = "G Standard",
            [new ArrangementTuning(2, 2, 2, 2, 2, 2, -999, -999, false)] = "F# Standard",
            [new ArrangementTuning(1, 1, 1, 1, 1, 1, -999, -999, false)] = "F Standard",
            [new ArrangementTuning(0, 0, 0, 0, 0, 0, -999, -999, false)] = "E Standard",
            [new ArrangementTuning(-1, -1, -1, -1, -1, -1, -999, -999, false)] = "Eb Standard",
            [new ArrangementTuning(-2, -2, -2, -2, -2, -2, -999, -999, false)] = "D Standard",
            [new ArrangementTuning(-3, -3, -3, -3, -3, -3, -999, -999, false)] = "C# Standard",
            [new ArrangementTuning(-4, -4, -4, -4, -4, -4, -999, -999, false)] = "C Standard",
            [new ArrangementTuning(-5, -5, -5, -5, -5, -5, -999, -999, false)] = "B Standard",
            [new ArrangementTuning(-6, -6, -6, -6, -6, -6, -999, -999, false)] = "Bb Standard",
            [new ArrangementTuning(-7, -7, -7, -7, -7, -7, -999, -999, false)] = "A Standard",
            [new ArrangementTuning(-8, -8, -8, -8, -8, -8, -999, -999, false)] = "Ab Standard",
            [new ArrangementTuning(-9, -9, -9, -9, -9, -9, -999, -999, false)] = "G Standard",
            [new ArrangementTuning(-10, -10, -10, -10, -10, -10, -999, -999, false)] = "F# Standard",
            [new ArrangementTuning(-11, -11, -11, -11, -11, -11, -999, -999, false)] = "F Standard",
            [new ArrangementTuning(-12, -12, -12, -12, -12, -12, -999, -999, false)] = "E Standard",

            // Alternate/Jank Bass Tuning equivalents
            [new ArrangementTuning(12, 12, 12, 12, 0, 0, -999, -999, true)] = "E Standard",
            [new ArrangementTuning(11, 11, 11, 11, 0, 0, -999, -999, true)] = "Eb Standard",
            [new ArrangementTuning(10, 10, 10, 10, 0, 0, -999, -999, true)] = "D Standard",
            [new ArrangementTuning(9, 9, 9, 9, 0, 0, -999, -999, true)] = "C# Standard",
            [new ArrangementTuning(8, 8, 8, 8, 0, 0, -999, -999, true)] = "C Standard",
            [new ArrangementTuning(7, 7, 7, 7, 0, 0, -999, -999, true)] = "B Standard",
            [new ArrangementTuning(6, 6, 6, 6, 0, 0, -999, -999, true)] = "Bb Standard",
            [new ArrangementTuning(5, 5, 5, 5, 0, 0, -999, -999, true)] = "A Standard",
            [new ArrangementTuning(4, 4, 4, 4, 0, 0, -999, -999, true)] = "Ab Standard",
            [new ArrangementTuning(3, 3, 3, 3, 0, 0, -999, -999, true)] = "G Standard",
            [new ArrangementTuning(2, 2, 2, 2, 0, 0, -999, -999, true)] = "F# Standard",
            [new ArrangementTuning(1, 1, 1, 1, 0, 0, -999, -999, true)] = "F Standard",
            [new ArrangementTuning(0, 0, 0, 0, 0, 0, -999, -999, true)] = "E Standard",
            [new ArrangementTuning(-1, -1, -1, -1, 0, 0, -999, -999, true)] = "Eb Standard",
            [new ArrangementTuning(-2, -2, -2, -2, 0, 0, -999, -999, true)] = "D Standard",
            [new ArrangementTuning(-3, -3, -3, -3, 0, 0, -999, -999, true)] = "C# Standard",
            [new ArrangementTuning(-4, -4, -4, -4, 0, 0, -999, -999, true)] = "C Standard",
            [new ArrangementTuning(-5, -5, -5, -5, 0, 0, -999, -999, true)] = "B Standard",
            [new ArrangementTuning(-6, -6, -6, -6, 0, 0, -999, -999, true)] = "Bb Standard",
            [new ArrangementTuning(-7, -7, -7, -7, 0, 0, -999, -999, true)] = "A Standard",
            [new ArrangementTuning(-8, -8, -8, -8, 0, 0, -999, -999, true)] = "Ab Standard",
            [new ArrangementTuning(-9, -9, -9, -9, 0, 0, -999, -999, true)] = "G Standard",
            [new ArrangementTuning(-10, -10, -10, -10, 0, 0, -999, -999, true)] = "F# Standard",
            [new ArrangementTuning(-11, -11, -11, -11, 0, 0, -999, -999, true)] = "F Standard",
            [new ArrangementTuning(-12, -12, -12, -12, 0, 0, -999, -999, true)] = "E Standard",

            [new ArrangementTuning(12, 14, 14, 14, 14, 14, -999, -999, false)] = "F# Drop E",
            [new ArrangementTuning(10, 12, 12, 12, 12, 12, -999, -999, false)] = "F Drop Eb",
            [new ArrangementTuning(10, 12, 12, 12, 12, 12, -999, -999, false)] = "Drop D",
            [new ArrangementTuning(9, 11, 11, 11, 11, 11, -999, -999, false)] = "Eb Drop Db",
            [new ArrangementTuning(8, 10, 10, 10, 10, 10, -999, -999, false)] = "D Drop C",
            [new ArrangementTuning(7, 9, 9, 9, 9, 9, -999, -999, false)] = "C# Drop B",
            [new ArrangementTuning(6, 8, 8, 8, 8, 8, -999, -999, false)] = "C Drop Bb",
            [new ArrangementTuning(5, 7, 7, 7, 7, 7, -999, -999, false)] = "B Drop A",
            [new ArrangementTuning(4, 6, 6, 6, 6, 6, -999, -999, false)] = "Bb Drop Ab",
            [new ArrangementTuning(3, 5, 5, 5, 5, 5, -999, -999, false)] = "A Drop G",
            [new ArrangementTuning(2, 4, 4, 4, 4, 4, -999, -999, false)] = "Ab Drop F#",
            [new ArrangementTuning(1, 3, 3, 3, 3, 3, -999, -999, false)] = "G Drop F",
            [new ArrangementTuning(0, 2, 2, 2, 2, 2, -999, -999, false)] = "F# Drop E",
            [new ArrangementTuning(-1, 1, 1, 1, 1, 1, -999, -999, false)] = "F Drop Eb",
            [new ArrangementTuning(-2, 0, 0, 0, 0, 0, -999, -999, false)] = "Drop D",
            [new ArrangementTuning(-3, -1, -1, -1, -1, -1, -999, -999, false)] = "Eb Drop Db",
            [new ArrangementTuning(-4, -2, -2, -2, -2, -2, -999, -999, false)] = "D Drop C",
            [new ArrangementTuning(-5, -3, -3, -3, -3, -3, -999, -999, false)] = "C# Drop B",
            [new ArrangementTuning(-6, -4, -4, -4, -4, -4, -999, -999, false)] = "C Drop Bb",
            [new ArrangementTuning(-7, -5, -5, -5, -5, -5, -999, -999, false)] = "B Drop A",
            [new ArrangementTuning(-8, -6, -6, -6, -6, -6, -999, -999, false)] = "Bb Drop Ab",
            [new ArrangementTuning(-9, -7, -7, -7, -7, -7, -999, -999, false)] = "A Drop G",
            [new ArrangementTuning(-10, -8, -8, -8, -8, -8, -999, -999, false)] = "Ab Drop F#",
            [new ArrangementTuning(-11, -9, -9, -9, -9, -9, -999, -999, false)] = "G Drop F",
            [new ArrangementTuning(-12, -10, -10, -10, -10, -10, -999, -999, false)] = "F# Drop E",
            [new ArrangementTuning(-13, -11, -11, -11, -11, -11, -999, -999, false)] = "F Drop Eb",
            [new ArrangementTuning(-14, -12, -12, -12, -12, -12, -999, -999, false)] = "Drop D",

            // Alternate/Jank Bass Tuning equivalents
            [new ArrangementTuning(12, 14, 14, 14, 0, 0, -999, -999, true)] = "F# Drop E",
            [new ArrangementTuning(10, 12, 12, 12, 0, 0, -999, -999, true)] = "F Drop Eb",
            [new ArrangementTuning(10, 12, 12, 12, 0, 0, -999, -999, true)] = "Drop D",
            [new ArrangementTuning(9, 11, 11, 11, 0, 0, -999, -999, true)] = "Eb Drop Db",
            [new ArrangementTuning(8, 10, 10, 10, 0, 0, -999, -999, true)] = "D Drop C",
            [new ArrangementTuning(7, 9, 9, 9, 0, 0, -999, -999, true)] = "C# Drop B",
            [new ArrangementTuning(6, 8, 8, 8, 0, 0, -999, -999, true)] = "C Drop Bb",
            [new ArrangementTuning(5, 7, 7, 7, 0, 0, -999, -999, true)] = "B Drop A",
            [new ArrangementTuning(4, 6, 6, 6, 0, 0, -999, -999, true)] = "Bb Drop Ab",
            [new ArrangementTuning(3, 5, 5, 5, 0, 0, -999, -999, true)] = "A Drop G",
            [new ArrangementTuning(2, 4, 4, 4, 0, 0, -999, -999, true)] = "Ab Drop F#",
            [new ArrangementTuning(1, 3, 3, 3, 0, 0, -999, -999, true)] = "G Drop F",
            [new ArrangementTuning(0, 2, 2, 2, 0, 0, -999, -999, true)] = "F# Drop E",
            [new ArrangementTuning(-1, 1, 1, 1, 0, 0, -999, -999, true)] = "F Drop Eb",
            [new ArrangementTuning(-2, 0, 0, 0, 0, 0, -999, -999, true)] = "Drop D",
            [new ArrangementTuning(-3, -1, -1, -1, 0, 0, -999, -999, true)] = "Eb Drop Db",
            [new ArrangementTuning(-4, -2, -2, -2, 0, 0, -999, -999, true)] = "D Drop C",
            [new ArrangementTuning(-5, -3, -3, -3, 0, 0, -999, -999, true)] = "C# Drop B",
            [new ArrangementTuning(-6, -4, -4, -4, 0, 0, -999, -999, true)] = "C Drop Bb",
            [new ArrangementTuning(-7, -5, -5, -5, 0, 0, -999, -999, true)] = "B Drop A",
            [new ArrangementTuning(-8, -6, -6, -6, 0, 0, -999, -999, true)] = "Bb Drop Ab",
            [new ArrangementTuning(-9, -7, -7, -7, 0, 0, -999, -999, true)] = "A Drop G",
            [new ArrangementTuning(-10, -8, -8, -8, 0, 0, -999, -999, true)] = "Ab Drop F#",
            [new ArrangementTuning(-11, -9, -9, -9, 0, 0, -999, -999, true)] = "G Drop F",
            [new ArrangementTuning(-12, -10, -10, -10, 0, 0, -999, -999, true)] = "F# Drop E",
            [new ArrangementTuning(-13, -11, -11, -11, 0, 0, -999, -999, true)] = "F Drop Eb",
            [new ArrangementTuning(-14, -12, -12, -12, 0, 0, -999, -999, true)] = "Drop D",

            [new ArrangementTuning(0, 0, 2, 2, 2, 0, -999, -999, false)] = "Open A",
            [new ArrangementTuning(-5, -3, -3, -1, 0, -1, -999, -999, false)] = "Open B",
            [new ArrangementTuning(-4, -2, -2, 0, 1, 0, -999, -999, false)] = "Open C",
            [new ArrangementTuning(-2, 0, 0, -1, -2, -2, -999, -999, false)] = "Open D",
            [new ArrangementTuning(0, 2, 2, 1, 0, 0, -999, -999, false)] = "Open E",
            [new ArrangementTuning(-4, -4, -2, -2, -2, 1, -999, -999, false)] = "Open F",
            [new ArrangementTuning(-2, -2, 0, 0, 0, -2, -999, -999, false)] = "Open G",

            // Alternate/Jank Bass Tuning equivalents
            [new ArrangementTuning(0, 0, 2, 2, 0, 0, -999, -999, true)] = "Open A",
            [new ArrangementTuning(-5, -3, -3, -1, 0, 0, -999, -999, true)] = "Open B",
            [new ArrangementTuning(-4, -2, -2, 0, 0, 0, -999, -999, true)] = "Open C",
            [new ArrangementTuning(-2, 0, 0, -1, 0, 0, -999, -999, true)] = "Open D",
            [new ArrangementTuning(0, 2, 2, 1, 0, 0, -999, -999, true)] = "Open E",
            [new ArrangementTuning(-4, -4, -2, -2, 0, 0, -999, -999, true)] = "Open F",
            [new ArrangementTuning(-2, -2, 0, 0, 0, 0, -999, -999, true)] = "Open G",

            [new ArrangementTuning(-2, 0, 0, 0, -2, -2, -999, -999, false)] = "DADGAD",
            [new ArrangementTuning(-4, -6, -8, -10, -11, -13, -999, -999, false)] = "Minor Third",
            [new ArrangementTuning(-8, -9, -10, -11, -11, -12, -999, -999, false)] = "Major Third",
            [new ArrangementTuning(0, 0, 0, 0, 1, 1, -999, -999, false)] = "Fourths",
            [new ArrangementTuning(-4, -3, -2, -1, 1, 2, -999, -999, false)] = "Aug Fourths",
            [new ArrangementTuning(-4, -2, 0, 2, 5, 7, -999, -999, false)] = "Fifths",
            [new ArrangementTuning(-2, 0, 0, 0, 0, -2, -999, -999, false)] = "Double Drop D",
            [new ArrangementTuning(-4, -2, -2, -2, 1, 0, -999, -999, false)] = "Nick Drake",
            [new ArrangementTuning(-4, 0, -2, 0, 1, 0, -999, -999, false)] = "C6 Modal",

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
            if (!Bass) { string_count = 6; } else { string_count = 4; }

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
                KeyValuePair<ArrangementTuning, string> tuningNamePair = _TuningNames.FirstOrDefault(kvp => kvp.Key.Equals(this));
                if (!tuningNamePair.Equals(default(KeyValuePair<ArrangementTuning, string>))) name = tuningNamePair.Value;

                if (name == "Custom Tuning")
                {
                    name = GetTuningFallback(new int[] { String0, String1, String2, String3, String4, String5 });
                }

                //Calculate estimated hz offset from cents offset, if nonzero
                if (CentsOffset != 0)
                {
                    name = $"{name}: A{Math.Floor(440d * Math.Pow(2d, CentsOffset / 1200d))}";
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

        public ArrangementTuning(int string0, int string1, int string2, int string3, int string4, int string5, int centsOffset, int capoFret, bool isBass)
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

        public ArrangementTuning(SongArrangement.ArrangementAttributes.ArrangementTuning tuning, int centsOffset, int capoFret, bool isBass)
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
        public int String0;
        public int String1;
        public int String2;
        public int String3;
        public int String4;
        public int String5;
        public int CentsOffset;
        public int CapoFret;
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
