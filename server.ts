import express from "express";
import type { NextFunction, Request, Response } from "express";
import "dotenv/config";
import mysql from "mysql2/promise";
import { generateText } from "ai";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

interface AuthTokenPayload extends jwt.JwtPayload {
  id: number;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthTokenPayload;
    }
  }
}

function getAuthUserId(req: Request): number | null {
  const id = req.user?.id;

  if (id === undefined || id === null) {
    return null;
  }

  const numericId = Number(id);

  return Number.isFinite(numericId) ? numericId : null;
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

////////////////////////////////////////////////
// ROOT
////////////////////////////////////////////////

app.get("/", (req: Request, res: Response) => {
  res.send("Hello from TypeScript 🚀");
});

////////////////////////////////////////////////
// AUTH MIDDLEWARE
////////////////////////////////////////////////

function auth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({
      message: "No token",
    });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET as string) as AuthTokenPayload;

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      message: "Invalid token",
    });
  }
}

////////////////////////////////////////////////
// REGISTER
////////////////////////////////////////////////

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

    const [result]: any = await pool.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword],
    );

    return res.status(201).json({
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
});

////////////////////////////////////////////////
// VERIFY TOKEN
////////////////////////////////////////////////

app.get("/auth/login", auth, async (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
  });
});

////////////////////////////////////////////////
// LOGIN
////////////////////////////////////////////////

app.post("/auth/login", async (req: Request, res: Response) => {
  try {
    const { username, password, googleuser, githubuser } = req.body;

    let user: any;

    /////////////////////////
    // GOOGLE LOGIN
    /////////////////////////

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

        user = {
          id: result.insertId,
          name: googleuser.username,
          email: googleuser.email,
        };
      } else {
        user = rows[0];
      }
    }

    /////////////////////////
    // GITHUB LOGIN
    /////////////////////////

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

        user = {
          id: result.insertId,
          name: githubuser.username,
          email: githubuser.email,
        };
      } else {
        user = rows[0];
      }
    }

    /////////////////////////
    // NORMAL LOGIN
    /////////////////////////

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

    /////////////////////////
    // TOKEN
    /////////////////////////

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      JWT_SECRET,
      {
        expiresIn: "2h",
      },
    );

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
});

////////////////////////////////////////////////
// AI
////////////////////////////////////////////////

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

////////////////////////////////////////////////
// GET BOARDS
////////////////////////////////////////////////

app.post("/api/board", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "No token",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {
      id: string;
    };

    const userId = decoded.id;

    const [board] = await pool.query(
      "SELECT title, description, color FROM boards WHERE user_id = ?",
      [userId],
    );

    return res.json({
      board,
    });
  } catch {
    return res.status(401).json({
      message: "Invalid token",
    });
  }
});

////////////////////////////////////////////////
// DASHBOARD GET
////////////////////////////////////////////////

app.get("/app/dashboard", auth, async (req: Request, res: Response) => {
  try {
    const userId = req.user?.id;

    const [boards]: any = await pool.query(
      "SELECT * FROM boards WHERE user_id = ?",
      [userId],
    );

    return res.json({
      success: true,
      boards,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

////////////////////////////////////////////////
// DASHBOARD POST
////////////////////////////////////////////////

app.post("/app/dashboard", auth, async (req: any, res: Response) => {
  try {
    const { title, description, color } = req.body;

    const user_id = req.user.id;

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

    return res.status(201).json({
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

    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

////////////////////////////////////////////////
// GET SINGLE BOARD
////////////////////////////////////////////////

app.get("/app/board/:id", auth, async (req: Request, res: Response) => {
  try {
    const boardId = req.params.id;

    const userId = req.user?.id;

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

    return res.json({
      board: rows[0],
      tasks,
    });
  } catch (err) {
    console.error(err);

    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});

////////////////////////////////////////////////
// DELETE BOARD
////////////////////////////////////////////////

app.delete("/app/board/:id", auth, async (req: Request, res: Response) => {
  try {
    const boardId = req.params.id;

    const userId = req.user?.id;

    const [result]: any = await pool.query(
      "DELETE FROM boards WHERE id = ? AND user_id = ?",
      [boardId, userId],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Board not found or not yours",
      });
    }

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

////////////////////////////////////////////////
// TOGGLE ACTIVE
////////////////////////////////////////////////

app.put("/app/board/:id", auth, async (req: Request, res: Response) => {
  try {
    const boardId = req.params.id;

    const userId = req.user?.id;

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

    const newActive = currentActive === 1 ? 0 : 1;

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

////////////////////////////////////////////////
// UPDATE BOARD DATA
////////////////////////////////////////////////

app.put(
  "/app/board/:boardId/changeExistData",
  auth,
  async (req: Request, res: Response) => {
    try {
      const { boardId } = req.params;

      const { title, description } = req.body;

      if (title && !description) {
        await pool.query("UPDATE boards SET title = ? WHERE id = ?", [
          title,
          boardId,
        ]);
      }

      if (description && !title) {
        await pool.query("UPDATE boards SET description = ? WHERE id = ?", [
          description,
          boardId,
        ]);
      }

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

      return res.status(200).json({
        success: true,
        title: board.title,
        description: board.description,
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  },
);

////////////////////////////////////////////////
// DELETE BOARD BY PARAM
////////////////////////////////////////////////

app.delete(
  "/app/board/:boardId/changeExistData",
  auth,
  async (req: Request, res: Response) => {
    try {
      const { boardId } = req.params;

      await pool.query("DELETE FROM boards WHERE id = ?", [boardId]);

      return res.status(200).json({
        success: true,
        message: "Board deleted successfully",
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  },
);

////////////////////////////////////////////////
// ADD TASK
////////////////////////////////////////////////

app.post("/app/board/:id", auth, async (req: Request, res: Response) => {
  try {
    const boardId = req.params.id;

    const { task } = req.body;

    if (!task) {
      return res.status(400).json({
        success: false,
        message: "Task is required",
      });
    }

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

////////////////////////////////////////////////
// DELETE USER
////////////////////////////////////////////////

app.post("/app/delete", async (req, res) => {
  try {
    const { name, password } = req.body;

    if (!name || !password) {
      return res.status(400).json({
        message: "Missing credentials",
      });
    }

    const [rows]: any = await pool.query("SELECT * FROM users WHERE name = ?", [
      name,
    ]);

    if (rows.length === 0) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const user = rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Wrong password",
      });
    }

    await pool.query("DELETE FROM users WHERE id = ?", [user.id]);

    return res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

////////////////////////////////////////////////
// SETTINGS PROFILE GET
////////////////////////////////////////////////

app.get("/app/settings/profile", auth, async (req: Request, res: Response) => {
  try {
    const userId = req.user?.id;

    const [rows]: any = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        bio,
        role,
        department,
        created_at,
        updated_at
      FROM users
      WHERE id = ?
      LIMIT 1
      `,
      [userId],
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const user = rows[0];

    return res.json({
      success: true,
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        bio: user.bio,
        role: user.role,
        department: user.department,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
      },
    });
  } catch (error) {
    console.error("[GET PROFILE ERROR]", error);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

////////////////////////////////////////////////
// SETTINGS ACCOUNT
////////////////////////////////////////////////

app.get("/app/settings/account", auth, async (req, res) => {
  try {
    const userId = (req as any).user.id;

    const [rows] = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        bio,
        role,
        department,
        created_at,
        updated_at
      FROM users
      WHERE id = ?
      `,
      [userId],
    );

    const users = rows as any[];

    if (users.length === 0) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    return res.json(users[0]);
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server error",
    });
  }
});

////////////////////////////////////////////////
// SETTINGS PROFILE UPDATE
////////////////////////////////////////////////

app.put("/app/settings/profile", auth, async (req: Request, res: Response) => {
  try {
    const userId = getAuthUserId(req);

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

    const { name, email, bio, role, department } = req.body;

    const [userRows] = await pool.query(
      "SELECT id FROM users WHERE id = ? LIMIT 1",
      [userId],
    );

    if (!(userRows as any[]).length) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    await pool.query(
      `
      UPDATE users
      SET
        name = ?,
        email = ?,
        bio = ?,
        role = ?,
        department = ?
      WHERE id = ?
      `,
      [
        name?.trim(),
        email?.trim(),
        bio || null,
        role || null,
        department || null,
        userId,
      ],
    );

    const [rows]: any = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        bio,
        role,
        department,
        created_at,
        updated_at
      FROM users
      WHERE id = ?
      LIMIT 1
      `,
      [userId],
    );

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      data: {
        id: rows[0].id,
        name: rows[0].name,
        email: rows[0].email,
        bio: rows[0].bio,
        role: rows[0].role,
        department: rows[0].department,
        createdAt: rows[0].created_at,
        updatedAt: rows[0].updated_at,
      },
    });
  } catch (err) {
    console.error("[PUT PROFILE ERROR]", err);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

////////////////////////////////////////////////
// SETTINGS PAGES
////////////////////////////////////////////////

app.get("/settings", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get("/settings/appearance", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get("/settings/billing", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get("/settings/integrations", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get(
  "/settings/notifications",
  auth,
  async (req: Request, res: Response) => {
    return res.status(200).json({
      success: true,
      message: "Valid token",
    });
  },
);

app.get("/settings/preferences", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get("/settings/privacy", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get("/settings/team", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get("/settings/security", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

app.get("/settings/advanced", auth, async (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Valid token",
  });
});

////////////////////////////////////////////////
// START SERVER
////////////////////////////////////////////////

app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);

  try {
    await pool.query("SELECT 1");

    console.log("✅ Successfully connected to MySQL");
  } catch (error) {
    console.error("❌ MySQL connection failed:", error);
  }
});
