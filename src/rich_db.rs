/// Rich Header Product ID database.
///
/// Maps (prod_id, build_id) pairs to human-readable descriptions like
/// `[C++] VS 2019 (build 29xxx)`.  Based on data from richprint, VB2019
/// paper ("Finding the Needle"), and Microsoft documentation.
///
/// Tool type lookup by prod_id.
const TOOL_TYPES: &[(u16, &str)] = &[
    // Imports
    (0x0001, "[IMP]"),
    // Exports (old linker)
    (0x0002, "[EXP]"),
    // Old linker
    (0x0004, "[LNK]"),
    // Assembler (MASM)
    (0x0003, "[ASM]"),
    (0x0007, "[ASM]"),
    (0x000F, "[ASM]"),
    (0x0045, "[ASM]"),
    (0x00AA, "[ASM]"),
    (0x00FF, "[ASM]"),
    (0x0100, "[ASM]"),
    (0x0101, "[ASM]"),
    // C compiler
    (0x0006, "[C]"),
    (0x000A, "[C]"),
    (0x0015, "[C]"),
    (0x001C, "[C]"),
    (0x006D, "[C]"),
    (0x0083, "[C]"),
    (0x00DA, "[C]"),
    (0x00DB, "[C]"),
    (0x00DC, "[C]"),
    (0x0104, "[C]"),
    (0x0105, "[C]"),
    (0x0106, "[C]"),
    // C++ compiler
    (0x0002, "[C++]"),
    (0x000B, "[C++]"),
    (0x0016, "[C++]"),
    (0x001D, "[C++]"),
    (0x006E, "[C++]"),
    (0x0084, "[C++]"),
    (0x00DD, "[C++]"),
    (0x00DE, "[C++]"),
    (0x00DF, "[C++]"),
    (0x0107, "[C++]"),
    (0x0108, "[C++]"),
    (0x0109, "[C++]"),
    // Resource compiler
    (0x0005, "[RES]"),
    (0x0009, "[RES]"),
    (0x005E, "[RES]"),
    (0x009D, "[RES]"),
    (0x0093, "[RES]"),
    // CVTRES
    (0x0008, "[CVTRES]"),
    (0x000C, "[CVTRES]"),
    (0x000D, "[CVTRES]"),
    (0x0060, "[CVTRES]"),
    (0x005D, "[CVTRES]"),
    // Linker
    (0x000E, "[LNK]"),
    (0x005F, "[LNK]"),
    (0x0078, "[LNK]"),
    (0x00E0, "[LNK]"),
    (0x00FC, "[LNK]"),
    (0x00FD, "[LNK]"),
    (0x0102, "[LNK]"),
    (0x010A, "[LNK]"),
    (0x010B, "[LNK]"),
    (0x010C, "[LNK]"),
    // LTCG (link-time code gen)
    (0x0014, "[LTCG]"),
    (0x00C7, "[LTCG]"),
    // POGO (profile-guided optimization)
    (0x0013, "[POGO]"),
    (0x00C6, "[POGO]"),
];

/// VS version ranges mapped by build_id.
/// (min_build, max_build, description)
const VS_VERSIONS: &[(u16, u16, &str)] = &[
    // VS 6.0
    (8047, 8799, "VS 6.0"),
    (8800, 9799, "VS 6.0 SP5-6"),
    // VS 2002 (7.0)
    (9466, 9500, "VS 2002 (7.0)"),
    // VS 2003 (7.1)
    (3077, 7000, "VS 2003 (7.1)"),
    // VS 2005 (8.0)
    (50320, 50399, "VS 2005 (8.0)"),
    (50400, 50799, "VS 2005 SP1"),
    // VS 2008 (9.0)
    (21022, 21099, "VS 2008 (9.0)"),
    (21100, 21299, "VS 2008 SP1"),
    (30729, 30749, "VS 2008 SP1"),
    // VS 2010 (10.0)
    (30319, 30399, "VS 2010 (10.0)"),
    (30400, 30499, "VS 2010 SP1"),
    (40219, 40299, "VS 2010 SP1"),
    // VS 2012 (11.0)
    (50727, 50799, "VS 2012 (11.0)"),
    (51025, 51199, "VS 2012 Update 1-4"),
    (51106, 51199, "VS 2012 Update 4"),
    // VS 2013 (12.0)
    (21005, 21020, "VS 2013 (12.0)"),
    // These build IDs overlap with 2008 range above, so they're checked
    // only when prod_id suggests a newer toolchain.
    // VS 2015 (14.0)
    (23026, 23099, "VS 2015 (14.0)"),
    (23506, 23599, "VS 2015 Update 1"),
    (23918, 23999, "VS 2015 Update 2"),
    (24210, 24299, "VS 2015 Update 3"),
    (24215, 24299, "VS 2015 Update 3.1"),
    // VS 2017 (15.x)
    (25017, 25099, "VS 2017 15.0"),
    (25506, 25599, "VS 2017 15.3"),
    (25831, 25899, "VS 2017 15.5"),
    (25835, 25899, "VS 2017 15.5"),
    (26128, 26199, "VS 2017 15.6"),
    (26428, 26499, "VS 2017 15.7"),
    (26726, 26799, "VS 2017 15.8"),
    (26905, 26999, "VS 2017 15.9"),
    // VS 2019 (16.x)
    (27508, 27599, "VS 2019 16.0"),
    (27702, 27799, "VS 2019 16.1"),
    (27905, 27999, "VS 2019 16.2"),
    (28105, 28199, "VS 2019 16.3"),
    (28314, 28399, "VS 2019 16.4"),
    (28610, 28699, "VS 2019 16.5"),
    (28805, 28899, "VS 2019 16.6"),
    (29110, 29199, "VS 2019 16.7"),
    (29333, 29399, "VS 2019 16.8"),
    (29336, 29399, "VS 2019 16.8"),
    (29910, 29999, "VS 2019 16.9"),
    (29913, 29999, "VS 2019 16.9"),
    (30036, 30099, "VS 2019 16.10"),
    (30133, 30199, "VS 2019 16.11"),
    // VS 2022 (17.x)
    (30401, 30499, "VS 2022 17.0"),
    (30818, 30899, "VS 2022 17.1"),
    (31104, 31199, "VS 2022 17.2"),
    (31329, 31399, "VS 2022 17.3"),
    (31332, 31399, "VS 2022 17.3"),
    (31629, 31699, "VS 2022 17.4"),
    (31937, 31999, "VS 2022 17.5"),
    (31938, 31999, "VS 2022 17.5"),
    (32215, 32299, "VS 2022 17.6"),
    (32532, 32599, "VS 2022 17.7"),
    (32824, 32899, "VS 2022 17.8"),
    (33135, 33199, "VS 2022 17.9"),
    (33433, 33499, "VS 2022 17.10"),
    (33801, 33899, "VS 2022 17.11"),
    (34108, 34199, "VS 2022 17.12"),
];

fn lookup_tool_type(prod_id: u16) -> &'static str {
    for &(id, name) in TOOL_TYPES {
        if id == prod_id {
            return name;
        }
    }
    "[???]"
}

fn lookup_vs_version(build_id: u16) -> Option<&'static str> {
    for &(min, max, ver) in VS_VERSIONS {
        if build_id >= min && build_id <= max {
            return Some(ver);
        }
    }
    None
}

/// Look up a Rich Header entry and return a human-readable description.
///
/// Examples:
/// - `[C++] VS 2019 (build 29110)`
/// - `[LNK] VS 2022 (build 31329)`
/// - `[???] Unknown (prod=0x00ff, build=12345)`
pub fn lookup_rich_entry(prod_id: u16, build_id: u16) -> String {
    let tool = lookup_tool_type(prod_id);
    match lookup_vs_version(build_id) {
        Some(ver) => format!("{} {} (build {})", tool, ver, build_id),
        None => {
            if tool == "[???]" {
                format!("[???] Unknown (prod={:#06x}, build={})", prod_id, build_id)
            } else {
                format!("{} Unknown version (build {})", tool, build_id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tool_and_version() {
        let desc = lookup_rich_entry(0x0107, 29110);
        assert!(desc.starts_with("[C++]"), "should be C++: {}", desc);
        assert!(desc.contains("VS 2019"), "should contain VS 2019: {}", desc);
        assert!(desc.contains("29110"), "should contain build id: {}", desc);
    }

    #[test]
    fn known_tool_unknown_version() {
        let desc = lookup_rich_entry(0x000E, 1);
        assert!(desc.starts_with("[LNK]"), "should be LNK: {}", desc);
        assert!(desc.contains("Unknown version"), "should say unknown version: {}", desc);
    }

    #[test]
    fn unknown_tool_and_version() {
        let desc = lookup_rich_entry(0xFFFF, 1);
        assert!(desc.starts_with("[???]"), "should be ???: {}", desc);
        assert!(desc.contains("Unknown"), "should say unknown: {}", desc);
    }

    #[test]
    fn resource_compiler() {
        let desc = lookup_rich_entry(0x0093, 50727);
        assert!(desc.starts_with("[RES]"), "should be RES: {}", desc);
    }
}
