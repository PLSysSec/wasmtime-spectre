use crate::settings::*;

#[inline(always)]
pub fn perform_transition_protection_in() {
    unsafe {
        llvm_asm!("lfence"
            :
            :
            :
            : "volatile"
        );
    }
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    let only_sandbox_isolation = get_spectre_only_sandbox_isolation();
    if !only_sandbox_isolation {
        let mitigation = get_spectre_mitigation();
        if mitigation == SpectreMitigation::LOADLFENCE
            || mitigation == SpectreMitigation::STRAWMAN
            || mitigation == SpectreMitigation::SFI
            || mitigation == SpectreMitigation::CET
        {
            // core switch to sandbox
            if mitigation == SpectreMitigation::SFI {
                //BTB flush
            }
        }
    }
}

#[inline(always)]
pub fn perform_transition_protection_out() {
    unsafe {
        llvm_asm!("lfence"
            :
            :
            :
            : "volatile"
        );
    }
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    let mitigation = get_spectre_mitigation();
    if mitigation == SpectreMitigation::LOADLFENCE
        || mitigation == SpectreMitigation::STRAWMAN
        || mitigation == SpectreMitigation::SFI
        || mitigation == SpectreMitigation::CET
    {
        // core switch to app
    }
}
