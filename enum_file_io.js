// TDLR; write events happen with FileOutputStream objects
// We can't get the filepath from this, so we need to hook the FileOutputStream constructor
// and build a HashMap of the file paths to look up later
var HashMap = Java.use('java.util.HashMap');
var fileMap = HashMap.$new(); 

Java.perform(function () {
    const debug = false
    const truncate_length = 100
  
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var File = Java.use('java.io.File');
    
    function logDebug(message) {
        if (debug) {
            console.log(`[Debug] ${message}`);
        }
    }

    // Hook the constructor that takes a file path (String)
    FileOutputStream.$init.overload('java.lang.String').implementation = function (filePath) {
        // Log the file path when the constructor is called
        console.log('FileOutputStream created with file path (String): ' + filePath);
        
        // Store the file path in the hashmap
        fileMap.put(this, filePath);
        
        // Call the original constructor
        return this.$init(filePath);
    };

    // Hook the constructor that takes a File object
    FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
        var filePath = file.getAbsolutePath().toString();  // Get file path from the File object
        
        // Log the file path when the constructor is called
        console.log('FileOutputStream created with File object, file path: ' + filePath);
        
        fileMap.put(this, filePath);  // Store the file path
        
        // Call the original constructor
        return this.$init(file);
    };

    // Hook the constructor that takes a FileDescriptor
    FileOutputStream.$init.overload('java.io.FileDescriptor').implementation = function (fileDescriptor) {
        // Log the creation of a FileOutputStream with a FileDescriptor
        console.log('FileOutputStream created with FileDescriptor');
        
        // Call the original constructor
        return this.$init(fileDescriptor);
    };

    // Hook the write method to track when data is written to the file
    FileOutputStream.write.overload('[B').implementation = function (data) {
        var filePath = fileMap.get(this); // Retrieve the file path from the map
        if (filePath) {
            console.log('Writing to file: ' + filePath);
        } else {
            console.log('Writing to an unknown file');
            // TODO get this hashmap to build properly
        }

        // Call the original write method
        return this.write(data);
    };

    // Hook the write method to log file path and content
    FileOutputStream.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        try {
            // Ensure 'this' is valid before proceeding with any logic
            if (this === null || this === undefined) {
                logDebug('FileOutputStream instance is null or undefined during write');
                return;
            }

            const content = decodeBytes(b, off, len);
            console.log(`[Java] Content: ${content}`);
        } catch (e) {
            logDebug(`FileOutputStream.write failed: ${e.message}`);
        }
        // Call the original write method
        this.write(b, off, len);
    };

    // Decode byte array to string
    function decodeBytes(bytes, off, len) {
        try {
            logDebug(`Decoding bytes: Offset: ${off}, Length: ${len}`);
            const jsArray = [];
            for (let i = off; i < off + len; i++) {
                const byte = bytes[i];
                if (byte === 0) break; // Stop at null bytes
                jsArray.push(byte);
            }
            const content = String.fromCharCode(...jsArray);
            logDebug(`Decoded content: ${content}`);
            return content.length > truncate_length ? content.substring(0, truncate_length) + '...' : content;
        } catch (e) {
            logDebug(`Decoding failed: ${e.message}`);
            return '<Non-UTF-8 content>';
        }
    }
});
