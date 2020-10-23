/*
 * Copyright 2020 Newlogic Impact Lab Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 *
 */

/**
 * This class is responsible for loading the library
 * at the extraction location where the jar is unzipped.
 * Core logic here is adapted from the lazysodium way of
 * loading its native library.
 */
package org.idpass.lite;

import org.idpass.lite.IDPassReader;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class IDPassLoader
{
    public static final int UNSPECIFIED = -1;
    public static final int MAC = 0;
    public static final int LINUX = 1;
    public static final int WINDOWS = 2;
    public static final int SOLARIS = 3;
    public static final int FREEBSD = 4;
    public static final int OPENBSD = 5;
    public static final int WINDOWSCE = 6;
    public static final int AIX = 7;
    public static final int ANDROID = 8;
    public static final int GNU = 9;
    public static final int KFREEBSD = 10;
    public static final int NETBSD = 11;

    private static int osType = UNSPECIFIED;

    private static void unzipFiles(final ZipInputStream zipInputStream,
                                   final Path unzipFilePath) throws IOException
    {
        try (BufferedOutputStream bos
                     = new BufferedOutputStream(new FileOutputStream(
                unzipFilePath.toAbsolutePath().toString()))) {
            byte[] bytesIn = new byte[1024];
            int read = 0;
            while ((read = zipInputStream.read(bytesIn)) != -1) {
                bos.write(bytesIn, 0, read);
            }
        }
    }

    private static void unzip(final String zipFilePath,
                              final String unzipLocation) throws IOException
    {
        if (!(Files.exists(Paths.get(unzipLocation)))) {
            Files.createDirectories(Paths.get(unzipLocation));
        }
        try (ZipInputStream zipInputStream
                     = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipInputStream.getNextEntry();
            while (entry != null) {
                Path filePath = Paths.get(unzipLocation, entry.getName());
                if (!entry.isDirectory()) {
                    filePath.getParent().toFile().mkdirs();
                    unzipFiles(zipInputStream, filePath);
                } else {
                    Files.createDirectories(filePath);
                }

                zipInputStream.closeEntry();
                entry = zipInputStream.getNextEntry();
            }
        }
    }

    public static File urlToFile(final String url)
    {
        String path = url;
        if (path.startsWith("jar:")) {
            // remove "jar:" prefix and "!/" suffix
            final int index = path.indexOf("!/");
            path = path.substring(4, index);
        }
        try {
            if ((osType == WINDOWS || osType == WINDOWSCE)
                    && path.matches("file:[A-Za-z]:.*")) {
                path = "file:/" + path.substring(5);
            }
            return new File(new URL(path).toURI());
        } catch (final MalformedURLException | URISyntaxException e) {
            // NB: URL is not completely well-formed.
        }
        if (path.startsWith("file:")) {
            // pass through the URL as-is, minus "file:" prefix
            path = path.substring(5);
            return new File(path);
        }
        throw new IllegalArgumentException("Invalid URL: " + url);
    }

    public static File urlToFile(final URL url)
    {
        return url == null ? null : urlToFile(url.toString());
    }

    private static File
    getFileFromJar(URL jarUrl, File outputDir, String pathInJar)
            throws IOException
    {
        File jar = urlToFile(jarUrl);
        unzip(jar.getAbsolutePath(), outputDir.getAbsolutePath());
        String filePath = outputDir.getAbsolutePath() + pathInJar;
        return new File(filePath);
    }

    public static boolean isJarFile(URL jarUrl)
    {
        if (jarUrl != null) {
            try (JarFile jarFile = new JarFile(jarUrl.getPath())) {
                // Successfully opened the jar file. Check if there's a manifest
                // This is probably not necessary
                Manifest manifest = jarFile.getManifest();
                if (manifest != null) {
                    return true;
                }
            } catch (IOException | SecurityException
                    | IllegalStateException e) {
                System.out.println("Exception getting JarFile object: "
                        + e.getMessage());
            }
        }
        return false;
    }

    public static URL getThisJarPath(final Class<?> c)
    {
        if (c == null)
            return null; // could not load the class

        // try the easy way first
        try {
            final URL codeSourceLocation
                    = c.getProtectionDomain().getCodeSource().getLocation();
            if (codeSourceLocation != null)
                return codeSourceLocation;
        } catch (final SecurityException e) {
            // NB: Cannot access protection domain.
        } catch (final NullPointerException e) {
            // NB: Protection domain or code source is null.
        }

        // NB: The easy way failed, so we try the hard way. We ask for the class
        // itself as a resource, then strip the class's path from the URL
        // string, leaving the base path.

        // get the class's raw resource path
        final URL classResource = c.getResource(c.getSimpleName() + ".class");
        if (classResource == null)
            return null; // cannot find class resource

        final String url = classResource.toString();
        final String suffix = c.getCanonicalName().replace('.', '/') + ".class";
        if (!url.endsWith(suffix))
            return null; // weird URL

        // strip the class's path from the URL string
        final String base = url.substring(0, url.length() - suffix.length());

        String path = base;

        // remove the "jar:" prefix and "!/" suffix, if present
        if (path.startsWith("jar:"))
            path = path.substring(4, path.length() - 2);

        try {
            return new URL(path);
        } catch (final MalformedURLException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static File createMainTempDirectory() throws IOException
    {
        Path path = Files.createTempDirectory("idpasslite");
        File dir = path.toFile();
        dir.mkdir();
        dir.deleteOnExit();
        return dir;
    }

    public static File copyToTempDirectory(String relativePath, URL jarUrl)
            throws IOException
    {
        // If the file does not start with a separator,
        // then let's make sure it does!
        if (!relativePath.startsWith(File.separator)) {
            relativePath = File.separator + relativePath;
        }

        // Create a "main" temporary directory in which
        // everything can be thrown in.
        File mainTempDir = createMainTempDirectory();

        // Create the required directories.
        mainTempDir.mkdirs();

        // get the file/directoryfrom a JAR
        return getFileFromJar(jarUrl, mainTempDir, relativePath);
    }

    /**
     * When the main app is bundled as a Fat-jar executable,
     * the idpass-lite.jar shall be inside the Fat-jar.
     * The idpass-lite.jar is extracted from the Fat-jar into
     * a temp directory and then the libidpasslite.so inside idpass-lite.jar
     * is further extracted into another temp directory.
     * The full path of libidpasslite.so is returned as a String
     * and gets System.loaded as a JNI.
     *
     * @param jarinjar URL of a jar within a jar
     * @return Returns the URL of the extracted inner jar.
     * @throws IOException File error
     */

    public static URL doubleExtract(String[] jarinjar) throws IOException
    {
        URL outerJar = new URL(jarinjar[0] + "!/");
        String innerJar = jarinjar[1];

        File tempDir = createMainTempDirectory();
        tempDir.mkdirs();

        File innerJarFile = getFileFromJar(outerJar, tempDir,innerJar);
        return innerJarFile.toURI().toURL();
    }

    public static String getLibrary() throws IOException
    {
        String idpasslib = "";
        String osName = System.getProperty("os.name");
        if (osName.startsWith("Linux")) {
            if ("dalvik".equals(System.getProperty("java.vm.name").toLowerCase())) {
                osType = ANDROID; // TODO
                // Native libraries on android must be bundled with the APK
                System.setProperty("jna.nounpack", "true");
            } else {
                osType = LINUX;
                idpasslib = "linux64/libidpasslite.so";
            }
        } else if (osName.startsWith("Mac") || osName.startsWith("Darwin")) {
            osType = MAC; // TODO
        } else if (osName.startsWith("Windows")) {
            osType = WINDOWS;
            idpasslib = "windows64/idpasslite.dll";
        }

        String idpasslibFullPath = "";
        URL url = IDPassLoader.getThisJarPath(IDPassReader.class);

        if (url.toString().startsWith("jar")) {
            String[] jarinjar = url.toString().split("!");
            url = doubleExtract(jarinjar);
        }

        if (IDPassLoader.isJarFile(url)) {
            // 1) create temp dir
            // 2) Unzip jar into temp dir
            // 3) Get absolute path of library from temp dir
            File file = copyToTempDirectory(idpasslib,url);
            idpasslibFullPath = file.getAbsolutePath();
        } else {
            // 1) Get absolute path of library from resource
            File file = new File(IDPassReader.class.getClassLoader().getResource(idpasslib).getFile());
            idpasslibFullPath = file.getAbsolutePath();
        }
        // TODO: cryptographically verify the native library!?
        // A signature can be embedded into the shared library
        // For example: `strings /path/to/libidpasslite.so | grep DXTRACKER`
        // returns the github commit hash where the library gets built
        return idpasslibFullPath;
    }
}
