use crate::settings::*;
extern "C" {
    pub fn pthread_yield();
}

#[inline(always)]
unsafe fn change_cores(cpuset: &libc::cpu_set_t) {
    let thread = libc::pthread_self();
    let s = libc::pthread_setaffinity_np(thread, libc::CPU_SETSIZE as libc::size_t, cpuset as *const libc::cpu_set_t);
    if s != 0 {
        panic!("Pthread affinity setting failed");
    }
    pthread_yield();
}

extern "C" {
    fn btb_flush();
}

#[inline(always)]
pub fn perform_transition_protection_in() {
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    let mitigation = get_spectre_mitigation();
    if mitigation != SpectreMitigation::NONE {
        unsafe {
            llvm_asm!("lfence"
                :
                :
                :
                : "volatile"
            );
        }

        if !get_spectre_only_sandbox_isolation() {
            if !get_spectre_disable_core_switching() {
                unsafe {
                    let cpuset = crate::settings::SANDBOX_CPUS.unwrap();
                    change_cores(&cpuset);
                }
            }
            if mitigation == SpectreMitigation::SFI && !get_spectre_disable_btbflush() {
                unsafe {
                    btb_flush();
                }
            }
        }
    }
}

#[inline(always)]
pub fn perform_transition_protection_out() {
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    let mitigation = get_spectre_mitigation();
    if mitigation != SpectreMitigation::NONE {
        unsafe {
            llvm_asm!("lfence"
                :
                :
                :
                : "volatile"
            );
        }

        if !get_spectre_only_sandbox_isolation() {
            if !get_spectre_disable_core_switching() {
                unsafe {
                    let cpuset = crate::settings::APPLICATION_CPUS.unwrap();
                    change_cores(&cpuset);
                }
            }
        }
    }
}
