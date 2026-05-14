import express from "express";
import type { NextFunction, Request, Response } from "express";
import "dotenv/config";
import mysql from "mysql2/promise";
import { generateText } from "ai";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
declare global {
  namespace Express {
    interface Request {
      user?: string | jwt.JwtPayload;
    }
  }
}

////////////////////////////////////////////////
const cleanEnv = (value?: string) =>
  value
    ?.trim()
    .replace(/;$/, "")
    .replace(/^['"]|['"]$/g, "");

const PORT = Number(cleanEnv(process.env.PORT)) || 5000;
const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();
const pool = mysql.createPool({
  host: cleanEnv(process.env.DB_HOST),
  user: cleanEnv(process.env.DB_USER),
  password: cleanEnv(process.env.DB_PASSWORD),
  database: cleanEnv(process.env.DB_NAME),
});
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not defined");
}
app.get("/", (req: Request, res: Response) => {
  res.send("Hello from TypeScript 🚀");
});

function auth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "No token" });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET as string);
    req.user = decoded; // now you have user info
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}
app.post("/auth/register", async (req: Request, res: Response) => {
  try {
    const { username, password, email } = req.body;
    const [existingRows] = await pool.query(
      "SELECT id FROM users WHERE name = ? OR email = ? LIMIT 1",
      [username, email],
    );
    if (Array.isArray(existingRows) && existingRows.length > 0) {
      return res.status(409).json({
        message: "The user already exists",
        success: false,
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword],
    );
    res.status(201).json({
      message: "User created successfully",
      success: true,
      data: result,
    });
  } catch (error: any) {
    console.error("REGISTER ERROR:", error);
    return res.status(500).json({
      message: "Internal server error",
      success: false,
      error: error?.message,
    });
  }
}); // register a new user
app.get("/auth/login", auth, async (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
  });
}); //check verity token
app.post("/auth/login", async (req: Request, res: Response) => {
  try {
    const { username, password, googleuser, githubuser } = req.body;

    let user: any;

    // =========================
    // GOOGLE LOGIN / SIGNUP
    // =========================
    if (googleuser?.email) {
      const [rows]: any = await pool.query(
        "SELECT * FROM users WHERE email = ? LIMIT 1",
        [googleuser.email],
      );

      if (!rows.length) {
        const [result]: any = await pool.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [googleuser.username, googleuser.email, null],
        );

        // ✅ IMPORTANT FIX: use insertId
        user = {
          id: result.insertId,
          name: googleuser.username,
          email: googleuser.email,
        };
      } else {
        user = rows[0];
      }
    }
    if (githubuser?.email) {
      const [rows]: any = await pool.query(
        "SELECT * FROM users WHERE email = ? LIMIT 1",
        [githubuser.email],
      );

      if (!rows.length) {
        const [result]: any = await pool.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [githubuser.username, githubuser.email, null],
        );

        // ✅ IMPORTANT FIX: use insertId
        user = {
          id: result.insertId,
          name: githubuser.username,
          email: githubuser.email,
        };
      } else {
        user = rows[0];
      }
    }

    // =========================
    // NORMAL LOGIN
    // =========================
    if (username && password && !user) {
      const [rows]: any = await pool.query(
        "SELECT * FROM users WHERE name = ? LIMIT 1",
        [username],
      );

      if (!rows.length) {
        return res.status(401).json({
          success: false,
          message: "Invalid username or password",
        });
      }

      user = rows[0];

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: "Invalid username or password",
        });
      }
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Missing login data",
      });
    }

    // =========================
    // TOKEN (same for both flows)
    // =========================
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "2h",
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        token,
      },
    });
  } catch (error: any) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error?.message,
    });
  }
}); // login a user
app.post("/app/ai", async (req: Request, res: Response) => {
  try {
    const { prompt } = req.body;
    const { text } = await generateText({
      model: "openai/gpt-4o-mini",
      prompt: `
      You are an AI that creates clear, practical plans for users.

Rules:
- Max 120 words
- Be specific and actionable
- Use simple language
- No fluff or motivation talk
- Output must be structured

Format:
Title: <short title>

Steps:
1. ...
2. ...
3. ...

Tips:
- ...
- ...

User request:
${prompt}
`,
    });

    res.json({
      success: true,
      plan: text,
    });
  } catch {
    res.status(500).json({
      success: false,
      message: "Failed to generate plan",
    });
  }
});
app.post("/api/board", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {
      id: string;
    };

    const userId = decoded.id;
    if (userId) {
      const [board] = await pool.query(
        "SELECT title,description,color FROM boards WHERE user_id = ?",
        [userId],
      );
      res.json({ board });
    }
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});
app.get("/app/dashboard", auth, async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "Authorization header missing",
      });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET as string,
    ) as jwt.JwtPayload;

    // Get user id directly from token
    const userId = decoded.id;

    const [boards]: any = await pool.query(
      "SELECT * FROM boards WHERE user_id = ?",
      [userId],
    );

    res.json({
      success: true,
      boards,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});
app.post("/app/dashboard", auth, async (req: any, res: Response) => {
  try {
    const { title, description, color } = req.body;

    const user_id = req.user.id; // from token

    if (!title || !color) {
      return res.status(400).json({
        success: false,
        message: "title and color are required",
      });
    }

    const [result]: any = await pool.query(
      "INSERT INTO boards (title, description, color, user_id) VALUES (?, ?, ?, ?)",
      [title, description || null, color, user_id],
    );

    res.status(201).json({
      success: true,
      message: "Board created successfully",
      data: {
        id: result.insertId,
        title,
        description,
        color,
        user_id,
      },
    });
  } catch (error: any) {
    console.error("DASHBOARD POST ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});
////////////////////////////////////////////////////////////////////
///param page
///////////////////////////////////////////////////////////////////
app.get("/app/board/:id", async (req: Request, res: Response) => {
  try {
    // Board id from URL params
    const boardId = req.params.id;

    // Token from header
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];

    // Decode JWT
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET as string,
    ) as jwt.JwtPayload;

    // User id from token
    const userId = decoded.id;

    // Get ONLY this user's board
    const [rows]: any = await pool.query(
      "SELECT * FROM boards WHERE id = ? AND user_id = ? LIMIT 1",
      [boardId, userId],
    );
    const [tasks]: any = await pool.query(
      "SELECT side_mission, complete FROM board_data WHERE board_id = ?",
      [boardId],
    );
    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Board not found",
      });
    }

    res.json({
      board: rows[0],
      tasks: tasks,
    });
  } catch (err) {
    console.error(err);

    res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});
////////////////////
//delete board
////////////////////
app.delete("/app/board/:id", async (req: Request, res: Response) => {
  try {
    // 1. Board ID from URL
    const boardId = req.params.id;

    // 2. Get token from header
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];

    // 3. Verify token
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET as string,
    ) as jwt.JwtPayload;

    const userId = decoded.id;

    // 4. Delete ONLY if it belongs to user
    const [result]: any = await pool.query(
      "DELETE FROM boards WHERE id = ? AND user_id = ?",
      [boardId, userId],
    );

    // 5. Check if anything was deleted
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Board not found or not yours",
      });
    }

    // 6. Success response
    return res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});
//////////////////////////
//update active
//////////////////////////
app.put("/app/board/:id", async (req: Request, res: Response) => {
  try {
    const boardId = req.params.id;

    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET as string,
    ) as jwt.JwtPayload;

    const userId = decoded.id;

    // 1. Get current active state
    const [rows]: any = await pool.query(
      "SELECT active FROM boards WHERE id = ? AND user_id = ?",
      [boardId, userId],
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Board not found",
      });
    }

    const currentActive = rows[0].active;

    // 2. Toggle it (1 -> 0, 0 -> 1)
    const newActive = currentActive === 1 ? 0 : 1;

    // 3. Update DB
    await pool.query(
      "UPDATE boards SET active = ? WHERE id = ? AND user_id = ?",
      [newActive, boardId, userId],
    );

    return res.json({
      success: true,
      active: newActive,
    });
  } catch (err) {
    console.error(err);

    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});
//param change page
app.put(
  "/app/board/:boardId/changeExistData",
  auth,
  async (req: Request, res: Response) => {
    try {
      const { boardId } = req.params;
      const { title, description } = req.body;

      // update only title
      if (title && !description) {
        await pool.query("UPDATE boards SET title = ? WHERE id = ?", [
          title,
          boardId,
        ]);
      }

      // update only description
      if (description && !title) {
        await pool.query("UPDATE boards SET description = ? WHERE id = ?", [
          description,
          boardId,
        ]);
      }

      // update both
      if (title && description) {
        await pool.query(
          "UPDATE boards SET title = ?, description = ? WHERE id = ?",
          [title, description, boardId],
        );
      }

      const [rows]: any = await pool.query(
        "SELECT title, description FROM boards WHERE id = ? LIMIT 1",
        [boardId],
      );

      const board = rows[0];

      res.status(200).json({
        success: true,
        title: board.title,
        description: board.description,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  },
);
//////////////////////////
//delete board
//////////////////////////
app.delete(
  "/app/board/:boardId/changeExistData",
  auth,
  async (req: Request, res: Response) => {
    try {
      const { boardId } = req.params;

      await pool.query("DELETE FROM boards WHERE id = ?", [boardId]);

      res.status(200).json({
        success: true,
        message: "Board deleted successfully",
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  },
);
///////////////////////////
//params insert
///////////////////////////
app.post("/app/board/:id", async (req: Request, res: Response) => {
  try {
    const boardId = req.params.id;

    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET as string,
    ) as jwt.JwtPayload;

    const userId = decoded.id;

    const { task } = req.body;

    if (!task) {
      return res.status(400).json({
        success: false,
        message: "Task is required",
      });
    }

    // Insert task
    await pool.query(
      "INSERT INTO board_data (side_mission, complete, board_id) VALUES (?, ?, ?)",
      [task, 0, boardId],
    );

    return res.json({
      success: true,
      message: "Task added successfully",
    });
  } catch (err) {
    console.error(err);

    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});
///////////////////////////
//delete
///////////////////////////
app.post("/app/delete", async (req, res) => {
  try {
    const { name, password } = req.body;

    if (!name || !password) {
      return res.status(400).json({ message: "Missing credentials" });
    }

    // 1. Find user
    const [rows]: any = await pool.query("SELECT * FROM users WHERE name = ?", [
      name,
    ]);
    console.log(rows);
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = rows[0];

    // 2. Check password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Wrong password" });
    }

    // 3. Delete user
    await pool.query("DELETE FROM users WHERE id = ?", [user.id]);
    return res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
////////////////////////////////////////////////////////////////////////////////////////////////
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);

  try {
    await pool.query("SELECT 1");
    console.log("✅ Successfully connected to MySQL");
  } catch (error) {
    console.error("❌ MySQL connection failed:", error);
  }
});
