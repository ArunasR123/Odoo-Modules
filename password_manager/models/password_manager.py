from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from odoo import models, fields, api, exceptions


class PasswordManager(models.Model):
    _name = 'password.manager'
    _description = 'Password Manager'
    _sql_constraints = [
        ('project_id_unique', 'UNIQUE(project_id)', "Password for this project is already assigned")
    ]

    password_pt = fields.Char(compute='_compute_password', readonly=False, string='Password')
    password_encrypted = fields.Binary(attachment=False)
    iv = fields.Binary(attachment=False)

    show_password = fields.Boolean(store=True)

    project_id = fields.Many2one('project.project', required=True, domain=[('password', '=', False)])
    user_ids = fields.Many2many('res.users', string='Users')

    _salt = b'\x12\xdb\xa2\x8a\x03\xe8_\xdf`\xbco(ki\xe5\xc5'

    @api.onchange('project_id')
    def _compute_user_ids(self):
        for record in self:
            record.user_ids = self.env['res.users'].search(
                [('partner_id', 'in', record.project_id.message_partner_ids.mapped('id'))])

    @api.model_create_multi
    def create(self, vals_list):
        if not all([vals['password_pt'] for vals in vals_list]):
            raise exceptions.UserError('Password can not be empty')

        for vals in vals_list:
            vals['password_encrypted'], vals['iv'] = self._encrypt_password(vals['password_pt'])

        return super().create(vals_list)

    def write(self, vals):
        if vals.get('password_pt'):
            vals['password_encrypted'], vals['iv'] = self._encrypt_password(vals['password_pt'])
        res = super(PasswordManager, self).write(vals)

        return res

    @api.model
    def _encrypt_password(self, password):

        master_password = self.env['ir.config_parameter'].search([('key', '=', 'database.uuid')], limit=1)[0].value
        key = PBKDF2(master_password, self._salt, dkLen=32)

        cipher = AES.new(key, AES.MODE_CBC)
        padded_pt = pad(bytes(password, 'utf-8'), AES.block_size)

        password_encrypted = cipher.encrypt(padded_pt)
        return password_encrypted, cipher.iv

    def _decrypt_password(self):

        master_password = self.sudo(True).env['ir.config_parameter'].search([('key', '=', 'database.uuid')], limit=1)[
            0].value
        key = PBKDF2(master_password, self._salt, dkLen=32)

        cipher = AES.new(key, AES.MODE_CBC, self.with_context({}, bin_size=False).iv)
        pt = unpad(cipher.decrypt(self.with_context({}, bin_size=False).password_encrypted), AES.block_size)
        return pt

    @api.depends('show_password')
    def _compute_password(self):
        for rec in self:
            if rec.password_encrypted and not rec.show_password:
                print('inside if')
                rec.password_pt = '●' * 8
            elif rec.show_password:
                rec.password_pt = rec._decrypt_password()
            else:
                rec.password_pt = ''

    def action_toggle_visibility(self):

        for record in self:
            print(record.password_pt)
            record.sudo(True).show_password ^= True

        return True


class ProjectProject(models.Model):
    _inherit = 'project.project'

    password = fields.One2many('password.manager', 'project_id')
