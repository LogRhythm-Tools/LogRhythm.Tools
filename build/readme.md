# :hammer: The Build Process

## :page_with_curl: `New-TestBuild.ps1`

The `New-TestBuild` script found in the root directory of this repository will satisfy most development use cases. Once a source file has been changed, calling `New-TestBuild` will create a new version of the module which is then immediately imported in the user's PowerShell scope.  Cleanup of old builds can be done by specifying the `-RemoveOld` switch.

## LrtBuilder Overview

The `New-TestBuild` script utilizes a small helper module called `LrtBuilder` created specifically for LogRhythm.Tools.   `LrtBuilder` can also be used to manage builds directly, or to install / uninstall them from the local computer.

The purpose of the `LrtBuilder` module is to facilitate testing, installation and release efforts by providing a consistent and reliable build process. This decouples the repository structure from the module structure, provides automated packaging / manifest creation, and gives developers a "point-in-time" verison of their builds which can be compared during the development process.

What does `LrtBuilder` do?

* A unique Build Id (guid) is assigned to the new build which will be used in the module's manifest file and by other `LrtBuilder` cmdlets to identify the build.
* A unique directory for the Build Id is created in `build\out` . All module files, public and private cmdlets, and`dll` files will be copied to this destination. A module manifest file based on `ModuleInfo.json` and parameters provided to `New-LrtBuild` will be generated in this directory.
* If the `Version` parameter is not provided, the value in `ModuleInfo.json` is used.
* Information about the new build is written to `build/BuildInfo.json`

## LrtBuilder Usage

Before running any LrtBuilder commands, you will need to import the `psm1` file located in the repository's `build` directory.

```PowerShell
PS C:\LogRhythm.Tools> Import-Module .\build\LrtBuilder.psm1
```

## `New-LrtBuild`

Creates a new build for this repository's module source (/src).

**Parameters:**

* `-Version` (x.y.z) Leaving out the version parameter uses the version in `ModuleInfo.json`
* `-ReleaseTag` Adds a release note to the module's manifest file.

**Example:**

```PowerShell
PS C:\> New-LrtBuild -Version 1.0.6 -ReleaseTag "Solved Collatz Conjecture"
```
