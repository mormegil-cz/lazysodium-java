<p align="center"><img width="260" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/lazysodium_large_transparent.png" /></p>

# Lazysodium for Java

Lazysodium is a **complete** Java (JNA) wrapper over the [Libsodium](https://github.com/jedisct1/libsodium) library that provides developers with a **smooth and effortless** cryptography experience.

Updated and improved fork by mormegil-cz.

[![Checks](https://github.com/mormegil-cz/lazysodium-java/actions/workflows/primary.yml/badge.svg)](https://github.com/mormegil-cz/lazysodium-java/actions/workflows/primary.yml)
![Maven Central](https://img.shields.io/maven-central/v/cz.mormegil/lazysodium-java?color=%23fff&label=Maven%20Central)

## Features

**This library is fully compatible with Kotlin.**

You can find an up-to-date feature list [here](https://github.com/terl/lazysodium-java/wiki/features).

## Quick start
Please view the [official documentation](https://github.com/terl/lazysodium-java/wiki/installation) for a more comprehensive guide.

The following example is for users of the build tool Gradle:

```groovy
// Top level build file
repositories {
    // Add this to the end of any existing repositories
    mavenCentral() 
}

// Project level dependencies section
dependencies {
    implementation "cz.mormegil:lazysodium-java:VERSION_NUMBER"
    implementation "net.java.dev.jna:jna:JNA_NUMBER"
}
```

Substitute `VERSION_NUMBER` for the version in this box:

![Maven Central](https://img.shields.io/maven-central/v/cz.mormegil/lazysodium-java?color=%23fff&label=Maven%20Central)

Substitute `JNA_NUMBER` for the [latest version of JNA](https://github.com/java-native-access/jna/tags).

## Documentation

Please view our [official documentation](https://github.com/terl/lazysodium-java/wiki) to get started.


## Examples
There are some example projects available [here](https://github.com/terl/lazysodium-java/tree/master/sample-app).


## Lazysodium for Android
We also have an Android implementation available at [Lazysodium for Android](https://github.com/terl/lazysodium-android). It has the same API as this library, so you can share code easily!

---

<a href="https://terl.co"><img width="100" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl.png" /></a>

Created by [Terl](https://terl.co).
Forked and modified by [Mormegil.cz](https://github.com/mormegil-cz/).
