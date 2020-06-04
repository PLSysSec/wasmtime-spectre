use crate::settings::{ SpectreSettings, SpectreMitigation, SpectrePHTMitigation};
use std::thread_local;
use std::cell::RefCell;
use std::mem::MaybeUninit;

extern "C" {
    pub fn pthread_yield();
}

thread_local! {
    static CORES_SET: RefCell<bool> = RefCell::new(false);
    static APPLICATION_CPUS: RefCell<Option<libc::cpu_set_t>> = RefCell::new(None);
    static SANDBOX_CPUS: RefCell<Option<libc::cpu_set_t>> = RefCell::new(None);
    static SPECTRE_RUNTIME_SETTINGS: RefCell<SpectreSettings> = RefCell::new(SpectreSettings {
        spectre_mitigation: SpectreMitigation::NONE,
        spectre_pht_mitigation: SpectrePHTMitigation::NONE,
        spectre_only_sandbox_isolation: false,
        spectre_no_cross_sbx_attacks: false,
        spectre_disable_core_switching: false,
        spectre_disable_btbflush: false,
    });
}

pub fn use_spectre_mitigation_core_partition(sandbox_cores: Option<usize>) {
    let already_set: bool = CORES_SET.with(|cores_set| {
        *cores_set.borrow()
    });

    if already_set && sandbox_cores.is_none() {
        return;
    }

    unsafe{
        let cpu_count = sysconf::raw::sysconf(sysconf::SysconfVariable::ScNprocessorsOnln).unwrap() as usize;

        let sandbox_cores = sandbox_cores.unwrap_or(cpu_count/2);
        if sandbox_cores >= cpu_count {
            panic!("Specified {} sandbox cores, system has {} cores and at least one must be given to the application",
                sandbox_cores, cpu_count);
        }

        //assuming we are on a hyperthreaded system
        if cpu_count % 2 != 0 {
            panic!("Expected even number of cpu cores on hyperthreaded system");
        }
        if sandbox_cores == 0 && sandbox_cores % 2 != 0 {
            panic!("Expected even non-zero number of sandbox cores on hyperthreaded system");
        }

        let application_cores = cpu_count - sandbox_cores;
        let mut application_core_arr = vec![false; cpu_count];
        for i in 0..application_cores/2 {
            application_core_arr[i] = true;
            // also assign hyperthreaded core
            application_core_arr[i + cpu_count/2] = true;
        }

        APPLICATION_CPUS.with(|app_cpus| {
            let mut cpuset = MaybeUninit::uninit().assume_init();
            libc::CPU_ZERO(&mut cpuset);
            for i in 0..cpu_count {
                if application_core_arr[i] {
                    libc::CPU_SET(i, &mut cpuset);
                }
            }
            *app_cpus.borrow_mut() = Some(cpuset);
        });

        SANDBOX_CPUS.with(|sbx_cpus| {
            let mut cpuset = MaybeUninit::uninit().assume_init();
            libc::CPU_ZERO(&mut cpuset);
            for i in 0..cpu_count {
                if !application_core_arr[i] {
                    libc::CPU_SET(i, &mut cpuset);
                }
            }
            *sbx_cpus.borrow_mut() = Some(cpuset);
        });

    }

    CORES_SET.with(|cores_set| {
        *cores_set.borrow_mut() = true;
    });
}

pub fn use_spectre_mitigation_runtime_settings(
    settings: SpectreSettings,
) {
    use_spectre_mitigation_core_partition(None);

    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        *spectre_runtime_settings.borrow_mut() = settings;
    });
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
    fn invoke_lfence();
}

#[inline(always)]
fn get_spectre_mitigation() -> SpectreMitigation {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        spectre_runtime_settings.borrow().spectre_mitigation
    })
}

#[inline(always)]
fn get_spectre_only_sandbox_isolation() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        spectre_runtime_settings.borrow().spectre_only_sandbox_isolation
    })
}

#[inline(always)]
fn get_spectre_disable_core_switching() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        spectre_runtime_settings.borrow().spectre_disable_core_switching
    })
}

#[inline(always)]
fn get_spectre_disable_btbflush() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        spectre_runtime_settings.borrow().spectre_disable_btbflush
    })
}

#[inline(always)]
fn get_spectre_no_cross_sbx_attacks() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        spectre_runtime_settings.borrow().spectre_no_cross_sbx_attacks
    })
}

#[inline(always)]
pub fn perform_transition_protection_in() {
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    let mitigation = get_spectre_mitigation();
    if mitigation != SpectreMitigation::NONE {
        unsafe {
            invoke_lfence();
        }

        if !get_spectre_only_sandbox_isolation() {
            if !get_spectre_disable_core_switching() {
                unsafe {
                    SANDBOX_CPUS.with(|cpuset| {
                        change_cores(&cpuset.borrow().unwrap());
                    });
                }
            }
            if mitigation == SpectreMitigation::SFI && !get_spectre_disable_btbflush() && !get_spectre_no_cross_sbx_attacks() {
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
            invoke_lfence();
        }

        if !get_spectre_only_sandbox_isolation() {
            if !get_spectre_disable_core_switching() {
                unsafe {
                    APPLICATION_CPUS.with(|cpuset| {
                        change_cores(&cpuset.borrow().unwrap());
                    });
                }
            }
        }
    }
}
