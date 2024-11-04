# noinspection PyUnusedLocal,PyStatementEffect
{
    'name': 'Password Manager',
    'depends': ['base', 'project'],
    'application': True,
    'data': [
        'security/security.xml',
        'security/ir.model.access.csv',
        'views/password_manager_views.xml',
        'views/password_manager_menu.xml'
    ],
    'category': 'Services/Password Manager',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': ['pycryptodome'],
    },
}
