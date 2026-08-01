const express = require("express");
const db = require("./db");
const router = express.Router();

router.get("/order/:id", async (req, res) => {
  const rows = await db.query(
    "SELECT * FROM orders WHERE id = " +
    req.params.id
  );
  res.json(rows);
});

module.exports = router;
