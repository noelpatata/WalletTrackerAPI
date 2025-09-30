from sqlalchemy import func, desc
from db import db
from models.Expense import Expense

class ExpenseRepository:
    
    @staticmethod
    def get_by_id(expense_id, session=None):
        sess = session or db.session
        fetched_expense = sess.query(Expense).get(expense_id)
        return fetched_expense
    
    @staticmethod
    def get_by_category(category_id, session=None):
        sess = session or db.session
        return (
            sess.query(Expense)
            .filter(Expense.category == category_id)
            .order_by(desc(Expense.expenseDate), desc(Expense.id))
            .all()
        )

    @staticmethod
    def get_total_by_category(category_id, session=None):
        sess = session or db.session
        total = (
            sess.query(func.sum(Expense.price))
            .filter(Expense.category == category_id)
            .scalar()
        )
        return total or 0.0

    @staticmethod
    def delete_all(session=None):
        sess = session or db.session
        sess.query(Expense).delete()
        sess.commit()

    @staticmethod
    def delete_by_id(expense_id, session=None):
        sess = session or db.session
        sess.query(Expense).filter(Expense.id == expense_id).delete()
        sess.commit()
