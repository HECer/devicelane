use device_development_mesh::apple_project_discovery::{
    AppleProjectDiscovery, ContainerKind, DiscoveryOutcome, ProjectDiscoveryError,
};
use device_development_mesh::preflight::{AppleTool, AppleToolRunner};
use std::env;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

const LIST: &str = include_str!("fixtures/v1/apple/xcodebuild-project-list.json");
const WORKSPACE_LIST: &str = include_str!("fixtures/v1/apple/xcodebuild-workspace-list.json");
const DESTINATIONS: &str = include_str!("fixtures/v1/apple/xcodebuild-destinations.txt");

#[test]
fn recognizes_project_schemes_configurations_and_destinations_from_fixtures() {
    let result = AppleProjectDiscovery::from_outputs(
        "Apps/Mesh App.xcodeproj",
        ContainerKind::Project,
        LIST,
        DESTINATIONS,
    )
    .unwrap();

    assert_eq!(result.container.path, "Apps/Mesh App.xcodeproj");
    assert_eq!(result.container.kind, ContainerKind::Project);
    assert_eq!(result.schemes[0].name, "Mesh App");
    assert_eq!(result.configurations[0].name, "Debug");
    assert_eq!(result.destinations[0].name, "Developer iPhone");
    assert_eq!(result.destinations[1].os.as_deref(), Some("18.0"));
    assert!(result.destinations[0].available);
    assert!(!result.destinations[2].available);
    assert!(
        result.destinations[2]
            .repair
            .as_deref()
            .unwrap()
            .contains("Install")
    );
}

#[test]
fn ambiguous_containers_and_schemes_return_stable_selection_ids() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("A.xcodeproj")).unwrap();
    fs::create_dir(root.path().join("B.xcworkspace")).unwrap();
    let runner = AppleToolRunner::new(
        root.path(),
        [(AppleTool::Xcodebuild, env::current_exe().unwrap())],
    )
    .unwrap();

    let first =
        AppleProjectDiscovery::discover(&runner, ".", None, None, Duration::from_secs(1)).unwrap();
    let second =
        AppleProjectDiscovery::discover(&runner, ".", None, None, Duration::from_secs(1)).unwrap();
    let (DiscoveryOutcome::Selection(first), DiscoveryOutcome::Selection(second)) = (first, second)
    else {
        panic!("selection expected")
    };
    assert_eq!(first.kind, "container");
    assert_eq!(first.options, second.options);
    assert_eq!(first.options[0].id, "project:A.xcodeproj");

    let parsed = AppleProjectDiscovery::from_outputs(
        "A.xcodeproj",
        ContainerKind::Project,
        LIST,
        DESTINATIONS,
    )
    .unwrap();
    let selection = parsed.select_scheme(None).unwrap_err();
    assert_eq!(selection.kind, "scheme");
    assert_eq!(selection.options[0].id, "scheme:Mesh%20App");

    let resolved = AppleProjectDiscovery::resolve_outputs(
        "A.xcodeproj",
        ContainerKind::Project,
        LIST,
        DESTINATIONS,
        Some("scheme:Mesh%20App"),
    )
    .unwrap();
    let DiscoveryOutcome::Ready(resolved) = resolved else {
        panic!("ready discovery expected")
    };
    assert_eq!(
        resolved
            .select_scheme(Some("scheme:Mesh%20App"))
            .unwrap()
            .name,
        "Mesh App"
    );
}

#[test]
fn recognizes_a_workspace_and_rejects_paths_outside_the_lease() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("Mesh Workspace.xcworkspace")).unwrap();
    let runner = AppleToolRunner::new(
        root.path(),
        [(AppleTool::Xcodebuild, env::current_exe().unwrap())],
    )
    .unwrap();

    assert_eq!(
        AppleProjectDiscovery::discover(&runner, "..", None, None, Duration::from_secs(1)),
        Err(ProjectDiscoveryError::OutsideWorkspace)
    );

    let parsed = AppleProjectDiscovery::from_outputs(
        "Mesh Workspace.xcworkspace",
        ContainerKind::Workspace,
        WORKSPACE_LIST,
        DESTINATIONS,
    )
    .unwrap();
    assert_eq!(parsed.container.kind, ContainerKind::Workspace);
    assert_eq!(
        parsed.xcodebuild_arguments("Mesh App"),
        vec![
            "-workspace",
            "Mesh Workspace.xcworkspace",
            "-scheme",
            "Mesh App"
        ]
    );
}

#[test]
fn excludes_container_symlinks_that_escape_the_lease() {
    let lease = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let target = outside.path().join("External.xcodeproj");
    fs::create_dir(&target).unwrap();
    let link = lease.path().join("External.xcodeproj");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&target, &link).unwrap();
    let runner = AppleToolRunner::new(
        lease.path(),
        [(AppleTool::Xcodebuild, env::current_exe().unwrap())],
    )
    .unwrap();

    assert_eq!(
        AppleProjectDiscovery::discover(&runner, ".", None, None, Duration::from_secs(1)),
        Err(ProjectDiscoveryError::ContainerNotFound)
    );
}

#[test]
fn preserves_spaces_and_metacharacters_as_single_xcodebuild_arguments() {
    let parsed = AppleProjectDiscovery::from_outputs(
        "Apps/O'Brien & Mesh.xcodeproj",
        ContainerKind::Project,
        LIST,
        DESTINATIONS,
    )
    .unwrap();
    assert_eq!(
        parsed.xcodebuild_arguments("Mesh App; echo unsafe"),
        vec![
            "-project",
            "Apps/O'Brien & Mesh.xcodeproj",
            "-scheme",
            "Mesh App; echo unsafe"
        ]
    );
}
