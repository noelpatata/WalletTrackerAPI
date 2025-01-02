import json
from flask import jsonify, request
from . import expenses_bp
from .Expense import Expense


# Endpoints
@expenses_bp.route('/expenses', methods=['GET'])
def get_expenses():
    expenses = Expense.get_all()
    expenses_json = [expense.serialize() for expense in expenses]  # Assuming a `to_dict` method
    return jsonify(expenses_json)


@expenses_bp.route('/expenses/<int:id>', methods=['GET'])
def get_expenses_by_id(id: int):
    expense = next((e for e in expenses if e['id'] == id), None)
    if expense is None:
        return jsonify({'error': 'Expense does not exist'}), 404
    return jsonify(expense)


@expenses_bp.route('/expenses', methods=['POST'])
def create_expenses():
    global nextexpensesId
    new_expense = request.get_json()
    if not all(key in new_expense for key in ['price', 'expenseDate', 'category']):
        return jsonify({'error': 'Invalid expense properties.'}), 400

    new_expense['id'] = nextexpensesId
    nextexpensesId += 1
    expenses.append(new_expense)

    return '', 201, {'location': f'/expenses/{new_expense["id"]}'}


@expenses_bp.route('/expenses/<int:id>', methods=['PUT'])
def update_expenses(id: int):
    expense = next((e for e in expenses if e['id'] == id), None)
    if expense is None:
        return jsonify({'error': 'Expense does not exist.'}), 404

    updated_expense = request.get_json()
    if not all(key in updated_expense for key in ['price', 'expenseDate', 'category']):
        return jsonify({'error': 'Invalid expense properties.'}), 400

    expense.update(updated_expense)
    return jsonify(expense)


@expenses_bp.route('/expenses/<int:id>', methods=['DELETE'])
def delete_expenses(id: int):
    global expenses
    expense = next((e for e in expenses if e['id'] == id), None)
    if expense is None:
        return jsonify({'error': 'Expense does not exist.'}), 404

    expenses = [e for e in expenses if e['id'] != id]
    return '', 204