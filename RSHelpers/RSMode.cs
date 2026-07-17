using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RockSnifferLib.RSHelpers
{
    /// <summary>
    /// Classification of the user's current Rocksmith mode-context, derived from
    /// gameStage (see RSMemoryReader.DeriveModeFromGameStage) — reliable across all
    /// states including menus, song-select, song-review, transitions, and Nonstop
    /// Play. Integer values 0..3 are preserved for external consumers.
    /// </summary>
    public enum RSMode
    {
        UNKNOWN,        // 0 - default / unrecognized gameStage
        LEARNASONG,     // 1 - learnasong, las_*, las_pause, las_songreview
        SCOREATTACK,    // 2 - scoreattack, sa_*, panel_bib, scoreattack_presongtuner
        MULTIPLAYER,    // 3 - mp_*, duet_*, h2h_*, split_game (full multiplayer support TBD)
        NONSTOPPLAY,    // 4 - nonstopplay, nsp_*, nonstopplayhub, nonstopplaygame
        GUITARCADE,     // 5 - gcpre, gcade, gcade_game, guitarcade_tuner, gc_*
        SESSION,        // 6 - sm_* (Session Mode)
        LESSONS,        // 7 - ge_*, getuner, pregametuner
        MENU            // 8 - titlescreen, profileselect, main, mainmenu, statsmenu,
                        //     shop, contentpanelchord, sidelist, tonedesigner*
    }
}
