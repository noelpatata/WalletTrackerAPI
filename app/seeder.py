import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from repositories.UserRepository import UserRepository
from services.UserService import UserService
from services.SeasonService import SeasonService
from services.ExpenseCategoryService import ExpenseCategoryService
from services.ExpenseService import ExpenseService
from services.ImporteService import ImporteService
from utils.Multitenant import get_tenant_session

app = create_app()

with app.app_context():
    if UserRepository.exists("admin"):
        print("User 'admin' already exists, skipping seeding.")
    else:
        user = UserService.register("admin", "adminadmin")
        print(f"Created user: admin (id={user.id})")

        session = get_tenant_session(user)

        today = datetime.now()
        season = SeasonService.get_or_create(today.year, today.month, session)
        print(f"Created season: {season.year}-{season.month:02d}")

        categories_data = [
            {"name": "Food", "sort_order": 1},
            {"name": "Transport", "sort_order": 2},
            {"name": "Housing", "sort_order": 3},
            {"name": "Entertainment", "sort_order": 4},
            {"name": "Health", "sort_order": 5},
        ]
        categories = []
        for cat_data in categories_data:
            cat = ExpenseCategoryService.create(cat_data["name"], session, cat_data["sort_order"])
            categories.append(cat)
            print(f"Created category: {cat.name}")

        y, m = today.year, today.month
        expenses_data = [
            {"price": 45.50, "expenseDate": f"{y}-{m:02d}-05", "category": categories[0].id, "description": "Groceries"},
            {"price": 12.00, "expenseDate": f"{y}-{m:02d}-08", "category": categories[1].id, "description": "Bus pass"},
            {"price": 800.00, "expenseDate": f"{y}-{m:02d}-01", "category": categories[2].id, "description": "Rent"},
            {"price": 30.00, "expenseDate": f"{y}-{m:02d}-15", "category": categories[3].id, "description": "Cinema"},
            {"price": 25.00, "expenseDate": f"{y}-{m:02d}-10", "category": categories[4].id, "description": "Pharmacy"},
        ]
        for exp_data in expenses_data:
            ExpenseService.create(
                price=exp_data["price"],
                expense_date=exp_data["expenseDate"],
                category_id=exp_data["category"],
                description=exp_data["description"],
                session=session
            )
        print(f"Created {len(expenses_data)} expenses.")

        importes_data = [
            {"concept": "Salary", "importeDate": f"{y}-{m:02d}-01", "amount": 2500.00, "balanceAfter": 2500.00},
            {"concept": "Freelance", "importeDate": f"{y}-{m:02d}-15", "amount": 500.00, "balanceAfter": 3000.00},
            {"concept": "Bonus", "importeDate": f"{y}-{m:02d}-20", "amount": 200.00, "balanceAfter": 3200.00},
        ]
        for imp_data in importes_data:
            ImporteService.create(
                concept=imp_data["concept"],
                importe_date=imp_data["importeDate"],
                amount=imp_data["amount"],
                balance_after=imp_data["balanceAfter"],
                season_id=season.id,
                session=session
            )
        print(f"Created {len(importes_data)} importes.")

        session.remove()
        print("Seeding complete.")
