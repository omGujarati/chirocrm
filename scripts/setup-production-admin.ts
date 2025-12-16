import { neon } from "@neondatabase/serverless";
import bcrypt from "bcrypt";

async function setupProductionAdmin() {
  // Use production database URL
  const databaseUrl = process.env.DATABASE_URL;
  
  if (!databaseUrl) {
    console.error("❌ DATABASE_URL not found");
    process.exit(1);
  }

  const sql = neon(databaseUrl);
  
  try {
    // Check if admin user already exists
    const existingUser = await sql`
      SELECT id FROM users WHERE email = 'drvahid9@gmail.com'
    `;
    
    if (existingUser.length > 0) {
      console.log("✅ Admin user already exists in production database");
      return;
    }
    
    // Hash the password
    const passwordHash = await bcrypt.hash("FirtsWatch123!", 10);
    
    // Create admin user
    await sql`
      INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_active, must_change_password)
      VALUES (
        'admin_vahid',
        'drvahid9@gmail.com',
        ${passwordHash},
        'Dr',
        'Vahid',
        'admin',
        true,
        true
      )
    `;
    
    console.log("✅ Production admin user created successfully!");
    console.log("📧 Email: drvahid9@gmail.com");
    console.log("🔑 Password: FirtsWatch123!");
    console.log("⚠️  You will be required to change your password on first login");
    
  } catch (error) {
    console.error("❌ Error setting up production admin:", error);
    process.exit(1);
  }
}

setupProductionAdmin();
