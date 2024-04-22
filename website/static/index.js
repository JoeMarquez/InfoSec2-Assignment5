function deleteNote(noteId) {
    fetch("/delete-note", {
      method: "POST",
      body: JSON.stringify({ noteId: noteId }),
    }).then((_res) => {
      window.location.href = "/";
    });
  }

  function deleteKey(keyId){
    fetch("/delete-key", {
      method: "POST",
      body: JSON.stringify({ keyId: keyId}),
    }).then((_res) => {
      window.location.href = "/generate_keys";
    });
  }

  function deleteFile(fileId){
    fetch("/delete-file", {
      method: "POST",
      body: JSON.stringify({ fileId: fileId}),
    }).then((_res) => {
      window.location.href = "/upload_files";
    });
  }