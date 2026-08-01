const express = require("express");
const db = require("./db");
const router = express.Router();

router.get("/order/:orderId", async (req, res) => {
  const { orderId } = req.params;
  const rows = await db.query("SELECT * FROM orders WHERE id = " + orderId);
  res.json(rows);
});

module.exports = router;
