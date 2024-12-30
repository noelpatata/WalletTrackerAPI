from flask import jsonify, request
from . import expenses_bp
from . import expenseDAO

# Simulación de base de datos en memoria
expenses = [
    {'id': 1, 'price': 2.5, 'expenseDate': "2024-02-28", 'category': 1},
    {'id': 2, 'price': 3.2, 'expenseDate': "2024-02-29", 'category': 1},
    {'id': 3, 'price': 4.1, 'expenseDate': "2024-01-01", 'category': 2}
]

nextexpensesId = 4


# Endpoints
@expenses_bp.route('/expenses', methods=['GET'])
def get_expenses():
    return jsonify(expenseDAO.getAll())


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