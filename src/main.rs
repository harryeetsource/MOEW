#![cfg(target_arch = "x86")]
#![feature(asm_experimental_arch)]
#![feature(naked_functions)]

use std::arch::{asm, naked_asm};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{env, fs, io};

const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

#[repr(C)]
struct SehRec {
    next: *mut SehRec,
    handler: usize,
}

// Global: monotonic stage counter so we can see the exception cascade
static STAGE_COUNTER: AtomicU32 = AtomicU32::new(0);

// Global: original fs:[0] SEH head saved at Stage 0 and restored at Final
static mut ORIGINAL_SEH: *mut SehRec = std::ptr::null_mut();

fn main() {
    println!("=========================================================");
    println!(" MOEW 3-Stage SEH Waterfall PoC (DEFANGED, BENIGN)");
    println!("---------------------------------------------------------");
    println!("- Stage 0:");
    println!("    * Save ORIGINAL_SEH = fs:[0]");
    println!("    * Install SEH[Stage1] on current frame");
    println!("    * Misaligned jump into blob1 => div-by-zero");
    println!("- Stage 1 Handler:");
    println!("    * Reached via Windows exception dispatch");
    println!("    * Launch notepad.exe (benign payload #1)");
    println!("    * Install SEH[Stage2]");
    println!("    * Misaligned jump into blob2 => div-by-zero");
    println!("- Stage 2 Handler:");
    println!("    * Reached via second exception dispatch");
    println!("    * Write marker file into %TEMP% (benign payload #2)");
    println!("    * Install SEH[Final]");
    println!("    * Misaligned jump into blob3 => div-by-zero");
    println!("- Final Handler:");
    println!("    * Reached via third exception dispatch");
    println!("    * Launch calc.exe (benign payload #3)");
    println!("    * Restore ORIGINAL_SEH into fs:[0]");
    println!("    * Exit process cleanly (no further exceptions).");
    println!("=========================================================\n");

    unsafe {
        stage0_install_and_trigger();
    }

    println!("\n[Main] If you see this line, the waterfall did not terminate as expected.");
}

// ---------------------------------------------------------
// Stage 0: Save original fs:[0], install Stage1 handler, misalign into blob1
// ---------------------------------------------------------
unsafe fn stage0_install_and_trigger() {
    // Start the stage counter at 0 so handlers are labeled 1,2,3,4...
    STAGE_COUNTER.store(0, Ordering::SeqCst);

    println!("[Stage 0] ENTER");

    // Save fs:[0] as ORIGINAL_SEH
    let mut old_head: *mut SehRec;
    asm!(
        "mov {old}, fs:[0]",
        old = out(reg) old_head,
        options(nostack, preserves_flags)
    );
    ORIGINAL_SEH = old_head;

    println!(
        "[Stage 0] ORIGINAL_SEH (fs:[0] before MOEW) = {:#010X}",
        ORIGINAL_SEH as u32
    );

    // Build SEH record #1 (Stage1 handler) on this frame
    let mut rec1 = SehRec {
        next: ORIGINAL_SEH,
        handler: stage1_handler as usize,
    };

    let p_rec1: *mut SehRec = &mut rec1;

    println!(
        "[Stage 0] Installing SEH[Stage1] at {:#010X}, handler = {:#010X}",
        p_rec1 as u32,
        rec1.handler as u32,
    );

    // fs:[0] = &rec1
    asm!(
        "mov fs:[0], {p}",
        p = in(reg) p_rec1,
        options(nostack, preserves_flags)
    );

    println!(
        "[Stage 0] fs:[0] now points to SEH[Stage1] record at {:#010X}",
        p_rec1 as u32
    );

    // Compute misaligned entry into blob1
    let blob1_base = blob1 as usize;
    let offset = 5usize; // Entry that decodes as div ecx (with ecx=0 => fault)
    let target = blob1_base + offset;

    println!(
        "[Stage 0] blob1 base = {:#010X}, offset = {}, misaligned target = {:#010X}",
        blob1_base as u32,
        offset,
        target as u32
    );
    println!("[Stage 0] Triggering first misaligned div-by-zero into blob1\n");

    asm!(
        "xor ecx, ecx",     // divisor = 0 for div-based fault
        "push {addr}",
        "ret",
        addr = in(reg) target,
        options(nostack)
    );

    // We should never reach this without an exception
    unreachable!();
}

// ---------------------------------------------------------
// Stage 1: executed as SEH handler for first fault
// ---------------------------------------------------------
unsafe extern "system" fn stage1_handler(
    _record: *mut u8,
    _frame: *mut u8,
    _context: *mut u8,
    _dispatcher: *mut u8,
) -> i32 {
    let stage = STAGE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    println!("---------------------------------------------------------");
    println!("[Stage {} Handler] ENTER (Stage1)", stage);
    println!("[Stage 1 Handler] Reached via KiUserExceptionDispatcher → RtlDispatchException → SEH");

    // Benign payload #1: launch notepad
    println!("[Stage 1 Handler] Launching notepad.exe (benign payload #1)");
    if let Err(e) = Command::new("notepad.exe").spawn() {
        println!("[Stage 1 Handler] Failed to launch notepad.exe: {e}");
    }

    // Build SEH record #2 (Stage2 handler) on this frame
    let mut rec2 = SehRec {
        next: std::ptr::null_mut(),
        handler: stage2_handler as usize,
    };

    // rec2.next = current fs:[0]
    asm!(
        "mov {old}, fs:[0]",
        old = out(reg) rec2.next,
        options(nostack, preserves_flags)
    );

    let p_rec2: *mut SehRec = &mut rec2;

    println!(
        "[Stage 1 Handler] Installing SEH[Stage2] at {:#010X}, handler = {:#010X}",
        p_rec2 as u32,
        rec2.handler as u32
    );
    println!(
        "[Stage 1 Handler] Previous SEH head (rec2.next) = {:#010X}",
        rec2.next as u32
    );

    // fs:[0] = &rec2
    asm!(
        "mov fs:[0], {p}",
        p = in(reg) p_rec2,
        options(nostack, preserves_flags)
    );

    println!(
        "[Stage 1 Handler] fs:[0] now points to SEH[Stage2] at {:#010X}",
        p_rec2 as u32
    );

    // Misaligned entry into blob2
    let blob2_base = blob2 as usize;
    let offset = 3usize; // Entry that decodes as div edx (with edx=0 => fault)
    let target = blob2_base + offset;

    println!(
        "[Stage 1 Handler] blob2 base = {:#010X}, offset = {}, misaligned target = {:#010X}",
        blob2_base as u32,
        offset,
        target as u32
    );
    println!("[Stage 1 Handler] Triggering second misaligned div-by-zero into blob2\n");

    asm!(
        "xor edx, edx",   // prepare state for div-based fault
        "push {addr}",
        "ret",
        addr = in(reg) target,
        options(nostack)
    );

    // Tell the OS we passed control back into the pipeline
    EXCEPTION_CONTINUE_SEARCH
}

// ---------------------------------------------------------
// Stage 2: executed as SEH handler for second fault
// ---------------------------------------------------------
unsafe extern "system" fn stage2_handler(
    _record: *mut u8,
    _frame: *mut u8,
    _context: *mut u8,
    _dispatcher: *mut u8,
) -> i32 {
    let stage = STAGE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    println!("---------------------------------------------------------");
    println!("[Stage {} Handler] ENTER (Stage2)", stage);
    println!("[Stage 2 Handler] Again, only reachable via SEH dispatch.");

    // Benign payload #2: write a marker file into %TEMP%
    println!("[Stage 2 Handler] Writing benign marker file into %TEMP% (payload #2)");
    if let Err(e) = write_temp_marker_file() {
        println!("[Stage 2 Handler] Failed to write marker file: {e}");
    }

    // Build SEH record #3 (Final handler) on this frame
    println!("[Stage 2 Handler] Installing SEH[Final_Handler]");

    let mut rec3 = SehRec {
        next: std::ptr::null_mut(),
        handler: final_handler as usize,
    };

    // rec3.next = current fs:[0]
    asm!(
        "mov {old}, fs:[0]",
        old = out(reg) rec3.next,
        options(nostack, preserves_flags)
    );

    let p_rec3: *mut SehRec = &mut rec3;

    println!(
        "[Stage 2 Handler] Installing SEH[Final] at {:#010X}, handler = {:#010X}",
        p_rec3 as u32,
        rec3.handler as u32
    );
    println!(
        "[Stage 2 Handler] Previous SEH head (rec3.next) = {:#010X}",
        rec3.next as u32
    );

    asm!(
        "mov fs:[0], {p}",
        p = in(reg) p_rec3,
        options(nostack, preserves_flags)
    );

    println!(
        "[Stage 2 Handler] fs:[0] now points to SEH[Final] at {:#010X}",
        p_rec3 as u32
    );

    // Misaligned entry into blob3
    let blob3_base = blob3 as usize;
    let offset = 3usize; // Entry that decodes as div ebx (with ebx=0 => fault)
    let target = blob3_base + offset;

    println!(
        "[Stage 2 Handler] blob3 base = {:#010X}, offset = {}, misaligned target = {:#010X}",
        blob3_base as u32,
        offset,
        target as u32
    );
    println!("[Stage 2 Handler] Triggering third misaligned div-by-zero into blob3\n");

    asm!(
        "xor ebx, ebx",
        "push {addr}",
        "ret",
        addr = in(reg) target,
        options(nostack)
    );

    EXCEPTION_EXECUTE_HANDLER
}

// ---------------------------------------------------------
// Final handler: benign payload #3, restore ORIGINAL_SEH and exit cleanly
// ---------------------------------------------------------
unsafe extern "system" fn final_handler(
    _record: *mut u8,
    _frame: *mut u8,
    _context: *mut u8,
    _dispatcher: *mut u8,
) -> i32 {
    let stage = STAGE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    println!("---------------------------------------------------------");
    println!("[Stage {} Handler] ENTER (Final)", stage);
    println!("[Final Handler] Reached after 3 staged, misaligned exceptions.");

    // Benign payload #3: launch calc.exe
    println!("[Final Handler] Launching calc.exe (benign payload #3)");
    if let Err(e) = Command::new("calc.exe").spawn() {
        println!("[Final Handler] Failed to launch calc.exe: {e}");
    }

    // Restore original SEH head
    println!("[Final Handler] Restoring ORIGINAL_SEH into fs:[0]");
    let orig = ORIGINAL_SEH;
    println!(
        "[Final Handler] ORIGINAL_SEH saved in Stage 0 = {:#010X}",
        orig as u32
    );

    asm!(
        "mov fs:[0], {p}",
        p = in(reg) orig,
        options(nostack, preserves_flags)
    );

    println!("[Final Handler] fs:[0] restored; MOEW SEH frames removed.");
    println!("[Final Handler] Exiting process cleanly (no further exceptions).\n");

    // Clean termination: no AV, no event log crash, waterfall ends here.
    process::exit(0);
}

// ---------------------------------------------------------
// Fault blobs: misaligned entry points that cause div-by-zero
// ---------------------------------------------------------

// Blob 1: when entered at +0 => mov eax, 0x10; div ecx; ret
//         when entered at +5 => div ecx (fault, ecx=0)
#[unsafe(naked)]
pub extern "C" fn blob1() {
    naked_asm! {
        ".byte 0xB8, 0x10, 0x00, 0x00, 0x00", // mov eax, 0x10
        ".byte 0xF7, 0xF1",                   // div ecx
        ".byte 0xC3",                         // ret
        ".byte 0x90, 0x90, 0x90",             // padding nops
    }
}

// Blob 2: when entered at +0 => push ebp; mov ebp, esp; div edx; ret
//         when entered at +3 => div edx (fault, edx=0)
#[unsafe(naked)]
pub extern "C" fn blob2() {
    naked_asm! {
        ".byte 0x55",                         // push ebp
        ".byte 0x8B, 0xEC",                   // mov ebp, esp
        ".byte 0xF7, 0xF2",                   // div edx
        ".byte 0xC3",                         // ret
        ".byte 0x90, 0x90, 0x90",             // padding nops
    }
}

// Blob 3: when entered at +0 => push ebx; mov ebx, eax; div ebx; ret
//         when entered at +3 => div ebx (fault, ebx=0)
#[unsafe(naked)]
pub extern "C" fn blob3() {
    naked_asm! {
        ".byte 0x53",                         // push ebx
        ".byte 0x8B, 0xD8",                   // mov ebx, eax
        ".byte 0xF7, 0xF3",                   // div ebx
        ".byte 0xC3",                         // ret
        ".byte 0x90, 0x90, 0x90",             // padding nops
    }
}

// ---------------------------------------------------------
// Benign Stage 2 helper: write marker file to %TEMP%
// ---------------------------------------------------------
fn write_temp_marker_file() -> io::Result<()> {
    let mut path = env::temp_dir();
    path.push("moew_stage2.txt");

    let content = "\
MOEW Stage 2 Marker
-------------------
This file was written by the Stage 2 SEH handler
as a benign demonstration payload.
";

    fs::write(&path, content)?;
    println!(
        "[Stage 2 Handler] Marker file written to: {}",
        path.display()
    );
    Ok(())
}
