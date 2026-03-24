import sys
import os
from datetime import date

sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from db import db
from models.User import User
from models.Season import Season
from models.ExpenseCategory import ExpenseCategory
from models.Expense import Expense
from models.Importe import Importe
from repositories.UserRepository import UserRepository
from utils.Cryptography import generate_private_key, generate_private_key_string, generate_public_key_string

app = create_app()

with app.app_context():
    #TODO this makes no sense because its not creating the user in the database
    if not UserRepository.exists("admin"):
        private_key = generate_private_key()
        user = User(
            username="admin",
            private_key=generate_private_key_string(private_key),
            public_key=generate_public_key_string(private_key),
            client_public_key=""
        )
        UserRepository.create_with_password(user, "adminadmin")
        print("Created user: admin")
    else:
        print("User 'admin' already exists, skipping.")

    #TODO this neither because engine_db is not initialised for the created user
    season = Season.query.filter_by(year=2026, month=3).first()
    if not season:
        season = Season(year=2026, month=3)
        db.session.add(season)
        db.session.commit()
        print("Created season: 2026-03")
    else:
        print("Season 2026-03 already exists, skipping.")

    categories_data = [
        {"name": "Food", "sortOrder": 1},
        {"name": "Transport", "sortOrder": 2},
        {"name": "Housing", "sortOrder": 3},
        {"name": "Entertainment", "sortOrder": 4},
        {"name": "Health", "sortOrder": 5},
    ]
    categories = []
    for cat_data in categories_data:
        existing = ExpenseCategory.query.filter_by(name=cat_data["name"]).first()
        if not existing:
            cat = ExpenseCategory(name=cat_data["name"], sortOrder=cat_data["sortOrder"])
            db.session.add(cat)
            db.session.flush()
            categories.append(cat)
            print(f"Created category: {cat_data['name']}")
        else:
            categories.append(existing)
            print(f"Category '{cat_data['name']}' already exists, skipping.")
    db.session.commit()

    expenses_data = [
        {"price": 45.50, "expenseDate": date(2026, 3, 5), "category": categories[0], "description": "Groceries"},
        {"price": 12.00, "expenseDate": date(2026, 3, 8), "category": categories[1], "description": "Bus pass"},
        {"price": 800.00, "expenseDate": date(2026, 3, 1), "category": categories[2], "description": "Rent"},
        {"price": 30.00, "expenseDate": date(2026, 3, 15), "category": categories[3], "description": "Cinema"},
        {"price": 25.00, "expenseDate": date(2026, 3, 10), "category": categories[4], "description": "Pharmacy"},
    ]
    for exp_data in expenses_data:
        expense = Expense(
            price=exp_data["price"],
            expenseDate=exp_data["expenseDate"],
            category=exp_data["category"].id,
            description=exp_data["description"],
            seasonId=season.id
        )
        db.session.add(expense)
    db.session.commit()
    print(f"Created {len(expenses_data)} expenses.")

    importes_data = [
        {"concept": "Salary", "importeDate": date(2026, 3, 1), "amount": 2500.00, "balanceAfter": 2500.00},
        {"concept": "Freelance", "importeDate": date(2026, 3, 15), "amount": 500.00, "balanceAfter": 3000.00},
        {"concept": "Bonus", "importeDate": date(2026, 3, 20), "amount": 200.00, "balanceAfter": 3200.00},
    ]
    for imp_data in importes_data:
        importe = Importe(
            concept=imp_data["concept"],
            importeDate=imp_data["importeDate"],
            amount=imp_data["amount"],
            balanceAfter=imp_data["balanceAfter"],
            seasonId=season.id
        )
        db.session.add(importe)
    db.session.commit()
    print(f"Created {len(importes_data)} importes.")

    print("Seeding complete.")
