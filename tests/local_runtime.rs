use device_development_mesh::local_runtime::{
    RuntimeEnvironment, RuntimePlatform, runtime_dir_for,
};
use std::path::PathBuf;

fn absolute_root() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn resolver_uses_the_installed_layout_for_each_platform() {
    let root = absolute_root();
    let home = root.path().join("home");
    let xdg = root.path().join("xdg");
    let local = root.path().join("local-app-data");
    for (platform, environment, suffix) in [
        (
            RuntimePlatform::Macos,
            RuntimeEnvironment {
                home: Some(home.clone()),
                xdg_runtime_dir: None,
                local_app_data: None,
            },
            PathBuf::from("Library/Application Support/DeviceLane/state/runtime"),
        ),
        (
            RuntimePlatform::Linux,
            RuntimeEnvironment {
                home: Some(home.clone()),
                xdg_runtime_dir: Some(xdg.clone()),
                local_app_data: None,
            },
            PathBuf::from("devicelane"),
        ),
        (
            RuntimePlatform::Windows,
            RuntimeEnvironment {
                home: None,
                xdg_runtime_dir: None,
                local_app_data: Some(local.clone()),
            },
            PathBuf::from("DeviceLane/service/runtime"),
        ),
    ] {
        assert_eq!(
            runtime_dir_for(platform, &environment).unwrap(),
            match platform {
                RuntimePlatform::Macos => home.join(suffix),
                RuntimePlatform::Linux => xdg.join(suffix),
                RuntimePlatform::Windows => local.join(suffix),
            }
        );
    }
}

#[test]
fn linux_empty_or_missing_xdg_uses_home_state_and_relative_bases_are_rejected() {
    let root = absolute_root();
    let home = root.path().join("home");
    for xdg_runtime_dir in [None, Some(PathBuf::new())] {
        assert_eq!(
            runtime_dir_for(
                RuntimePlatform::Linux,
                &RuntimeEnvironment {
                    home: Some(home.clone()),
                    xdg_runtime_dir,
                    local_app_data: None
                }
            )
            .unwrap(),
            home.join(".local/state/devicelane/runtime/devicelane"),
        );
    }
    let relative = RuntimeEnvironment {
        home: Some(home),
        xdg_runtime_dir: Some(PathBuf::from("relative")),
        local_app_data: None,
    };
    assert!(runtime_dir_for(RuntimePlatform::Linux, &relative).is_err());
}

#[test]
fn resolver_requires_an_absolute_required_base_without_creating_it() {
    let root = absolute_root();
    let missing_home = root.path().join("missing-home");
    let relative_local = RuntimeEnvironment {
        home: None,
        xdg_runtime_dir: None,
        local_app_data: Some(PathBuf::from("relative")),
    };
    assert!(runtime_dir_for(RuntimePlatform::Windows, &relative_local).is_err());
    assert!(
        runtime_dir_for(
            RuntimePlatform::Macos,
            &RuntimeEnvironment {
                home: None,
                xdg_runtime_dir: None,
                local_app_data: None
            }
        )
        .is_err()
    );
    assert_eq!(
        runtime_dir_for(
            RuntimePlatform::Linux,
            &RuntimeEnvironment {
                home: Some(missing_home.clone()),
                xdg_runtime_dir: None,
                local_app_data: None
            }
        )
        .unwrap(),
        missing_home.join(".local/state/devicelane/runtime/devicelane")
    );
    assert!(!missing_home.exists());
}

#[test]
fn linux_valid_xdg_does_not_require_home() {
    let root = absolute_root();
    let xdg = root.path().join("xdg");
    assert_eq!(
        runtime_dir_for(
            RuntimePlatform::Linux,
            &RuntimeEnvironment {
                home: None,
                xdg_runtime_dir: Some(xdg.clone()),
                local_app_data: None,
            },
        )
        .unwrap(),
        xdg.join("devicelane")
    );
}

#[test]
fn macos_ignores_foreign_xdg_runtime() {
    let root = absolute_root();
    let home = root.path().join("home");
    assert_eq!(
        runtime_dir_for(
            RuntimePlatform::Macos,
            &RuntimeEnvironment {
                home: Some(home.clone()),
                xdg_runtime_dir: Some(root.path().join("foreign-xdg")),
                local_app_data: None,
            },
        )
        .unwrap(),
        home.join("Library/Application Support/DeviceLane/state/runtime")
    );
}

#[test]
fn macos_and_linux_fallback_reject_relative_home() {
    for platform in [RuntimePlatform::Macos, RuntimePlatform::Linux] {
        assert!(
            runtime_dir_for(
                platform,
                &RuntimeEnvironment {
                    home: Some(PathBuf::from("relative-home")),
                    xdg_runtime_dir: None,
                    local_app_data: None,
                },
            )
            .is_err(),
            "{platform:?} accepted a relative HOME"
        );
    }
}

#[test]
fn windows_requires_localappdata_even_when_home_and_xdg_exist() {
    let root = absolute_root();
    assert!(
        runtime_dir_for(
            RuntimePlatform::Windows,
            &RuntimeEnvironment {
                home: Some(root.path().join("home")),
                xdg_runtime_dir: Some(root.path().join("xdg")),
                local_app_data: None,
            },
        )
        .is_err()
    );
}
