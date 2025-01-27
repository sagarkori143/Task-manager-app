const noteRoutes = require("express").Router();
import dataModel, { findById, findByIdAndUpdate, findOneAndUpdate } from "../Models/DataModel";

noteRoutes.get("/getNote", async (req, res) => {
  const { _id } = req.user;
  const newNote = new dataModel({
    _id: _id,
  });
  let note = await findById(_id);
  if (!note) note = await newNote.save();
  console.log(note.notes);
  res.json(note.notes);
});

noteRoutes.post("/postNote", async (req, res) => {
  const { _id } = req.user;
  const note = req.body;
  await findByIdAndUpdate({ _id: _id }, { $push: { notes: note } })
    .catch((err) => {
      console.log(err);
    });
  res.json({ success: "Posted Successfully" });
});

noteRoutes.patch("/updateNote/:id", async (req, res) => {
  const { id } = req.params;
  const { newText } = req.body;
  await findOneAndUpdate(
      { "notes.id": id },
      {
        $set: {
          "notes.$.noteText": newText,
        },
      },
      { new: true }
    )
    .catch((err) => {
      console.log(err);
    });
  res.json({ success: "Updated successfully" });
});

noteRoutes.delete("/deleteNote/:id", async (req, res) => {
  const { _id } = req.user;
  const { id } = req.params;
  await findByIdAndUpdate(_id, { $pull: { notes: { id: id } } })
    .catch((err) => {
      console.log(err);
    });
  res.json({ success: "Deleted successfully" });
});

export default noteRoutes;
