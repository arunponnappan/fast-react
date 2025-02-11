import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.core.database import AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole

async def create_admin():
    async with AsyncSessionLocal() as db:  # Open DB session
        async with db.begin():
            # Check if an admin user already exists
            result = await db.execute(select(User).filter(User.role == UserRole.admin))
            existing_admin = result.scalars().first()
            if existing_admin:
                print("Admin user already exists.")
                return

            # Create admin user
            admin_user = User(
                username="admin",
                email="admin@example.com",
                hashed_password=get_password_hash("admin123"),
                role=UserRole.admin,
                status="Active"
            )
            db.add(admin_user)
            await db.commit()
            print("✅ Admin user created: admin@example.com / admin123")

# Run the script
asyncio.run(create_admin())
