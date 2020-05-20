use crate::settings::*;

#[inline(always)]
unsafe fn change_affinity(cpuset: &libc::cpu_set_t) {
    let thread = libc::pthread_self();
    let s = libc::pthread_setaffinity_np(thread, libc::CPU_SETSIZE as libc::size_t, cpuset as *const libc::cpu_set_t);
    if s != 0 {
        panic!("Pthread affinity setting failed");
    }
}

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
            if !get_spectre_disable_core_switching() {
                unsafe {
                    let cpuset = crate::settings::SANDBOX_CPUS.unwrap();
                    change_affinity(&cpuset);
                }
            }
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
        if !get_spectre_disable_core_switching() {
            unsafe {
                let cpuset = crate::settings::APPLICATION_CPUS.unwrap();
                change_affinity(&cpuset);
            }
        }
    }
}
