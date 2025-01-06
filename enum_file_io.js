'use strict';

var HashMap = Java.use('java.util.HashMap');
var fileMap = HashMap.$new(); 

Java.perform(function () {
    const debug = false;
    const truncate_length = 10;

    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var File = Java.use('java.io.File');

    function logDebug(message) {
        if (debug) {
            console.log('[Debug] ' + message);
        }
    }

    function storeFileOutputStreamInstance(fosThis, filePath) {
        //var uniqueId = generateUniqueId();
        //fileMap.put(fosThis, { id: uniqueId, path: filePath });
        fileMap.put(fosThis.toString(), filePath)
        logDebug('Storing FOS in map -> ID: ' + fosThis.toString() + ' Path: ' + (filePath || 'Unknown'));
    }

    function getFileOutputStreamInfo(fosThis) {
        logDebug('Do we have ' + fosThis.toString() + " in our map?")
        logDebug('Uhhh there is ' +fileMap.get(fosThis.toString()))
        var info = fileMap.get(fosThis.toString());
        if (info) {
            return info;
        }
        return undefined;
    }

    /**************************************************************************
     *                       Hooking FileOutputStream                         *
     **************************************************************************/
    // https://docs.oracle.com/javase/8/docs/api/java/io/FileOutputStream.html
    
    // --- Overload #1: FileOutputStream(String path)
    FileOutputStream.$init.overload('java.lang.String').implementation = function (filePath) {
        console.log('FileOutputStream created with file path (String): ' + filePath);
        storeFileOutputStreamInstance(this, filePath);
        return this.$init(filePath);
    };

    // --- Overload #2: FileOutputStream(String path, boolean append)
    FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function (filePath, append) {
        console.log('FileOutputStream created with file path (String): ' + filePath + ', append=' + append);
        storeFileOutputStreamInstance(this, filePath);
        return this.$init(filePath, append);
    };

    // --- Overload #3: FileOutputStream(File file)
    FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
        var filePath = file.getAbsolutePath().toString();
        console.log('FileOutputStream created with File object, file path: ' + filePath);
        storeFileOutputStreamInstance(this, filePath);
        return this.$init(file);
    };

    // --- Overload #4: FileOutputStream(File file, boolean append)
    FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function (file, append) {
        var filePath = file.getAbsolutePath().toString();
        console.log('FileOutputStream created with File object, file path: ' + filePath + ', append=' + append);
        storeFileOutputStreamInstance(this, filePath);
        return this.$init(file, append);
    };

    // --- Overload #5: FileOutputStream(FileDescriptor fd)
    FileOutputStream.$init.overload('java.io.FileDescriptor').implementation = function (fd) {
        console.log('FileOutputStream created with FileDescriptor (no known path)');
        storeFileOutputStreamInstance(this, 'FileDescriptor-Only');
        return this.$init(fd);
    };

    // --- Overload #6: FileOutputStream(FileDescriptor fd, boolean)
    //     Actually doesn't exist in many Android versions, but included just in case:
    try {
        FileOutputStream.$init.overload('java.io.FileDescriptor', 'boolean').implementation = function (fd, append) {
            console.log('FileOutputStream created with FileDescriptor, append=' + append);
            storeFileOutputStreamInstance(this, 'FileDescriptor-Only');
            return this.$init(fd, append);
        };
    } catch (e) {
        logDebug('No overload found for FileOutputStream(FileDescriptor, boolean) in this API level.');
    }

    /**************************************************************************
     *                           Hooking write()                              *
     **************************************************************************/

    // write(byte[])
    FileOutputStream.write.overload('[B').implementation = function (data) {
        var info = getFileOutputStreamInfo(this);
        if (info) {
            console.log('Writing to file Path ' + info);
        } else {
            console.log('Writing to an unknown file (not in map)');
        }

        return this.write(data);
    };

    // write(byte[], int, int)
    FileOutputStream.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        var info = getFileOutputStreamInfo(this);
        if (info) {
            console.log('Writing to file Path ' + info + 
                        ' | Bytes: ' + len + ' (offset=' + off + ')');
        } else {
            console.log('Writing to an unknown file (not in map)');
        }

        // Try to decode as UTF-8 and print partial output
        if (debug) {
            try {
                const content = decodeBytes(b, off, len);
                console.log('[Java] Content: ' + content);
            } catch (e) {
                logDebug('Decoding write data failed: ' + e.message);
            }
        }

        return this.write(b, off, len);
    };

    // Optionally: write(int)
    // If you care about calls to write single bytes:
    try {
        FileOutputStream.write.overload('int').implementation = function (oneByte) {
            var info = getFileOutputStreamInfo(this);
            if (info) {
                console.log('Writing 1 byte to file Path: ' + info);
            } else {
                console.log('Writing 1 byte to an unknown file (not in map)');
            }
            return this.write(oneByte);
        };
    } catch (e) {
        // Not all Java versions may define write(int) for FileOutputStream
        logDebug('write(int) not found or hooking failed: ' + e.message);
    }

    /**************************************************************************
     *                          Hooking close()                               *
     *    Removes the entry from our fileMap to avoid memory bloat.          *
     **************************************************************************/
    FileOutputStream.close.implementation = function () {
        var info = fileMap.get(this.toString());
        if (info) {
            console.log('Closing FileOutputStream at Path: ' + info);
        } else {
            console.log('Closing an unknown FileOutputStream');
        }

        // Remove from map
        fileMap.remove(this);

        // Call original
        return this.close();
    };

    /**
     * Decode a portion of the byte array to a (truncated) UTF-8 string.
     */
    function decodeBytes(bytes, off, len) {
        try {
            logDebug('Decoding bytes: Offset=' + off + ', Length=' + len);
            const jsArray = [];
            for (let i = off; i < off + len; i++) {
                const byteVal = bytes[i];
                // Stop if we reach a null byte, purely optional logic
                if (byteVal === 0) break;
                jsArray.push(byteVal);
            }
            const content = String.fromCharCode.apply(String, jsArray);
            logDebug('Decoded content: ' + content);

            // Truncate if needed
            return (content.length > truncate_length)
                ? content.substring(0, truncate_length) + '...'
                : content;
        } catch (e) {
            logDebug('Decoding failed: ' + e.message);
            return '<Non-UTF-8 content>';
        }
    }
});
