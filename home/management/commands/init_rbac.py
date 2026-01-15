"""
Management command to initialize the RBAC system
Creates roles, permissions, and default admin user
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from home.models import User, Role, Permission, RolePermission
import getpass


class Command(BaseCommand):
    help = 'Initialize RBAC system with roles, permissions, and default admin'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            help='Admin username (will prompt if not provided)',
        )
        parser.add_argument(
            '--email',
            type=str,
            help='Admin email (will prompt if not provided)',
        )
        parser.add_argument(
            '--skip-admin',
            action='store_true',
            help='Skip admin user creation',
        )

    def handle(self, *args, **options):
        self.stdout.write('Initializing RBAC system...\n')
        
        with transaction.atomic():
            # Create Permissions
            self.stdout.write('Creating permissions...')
            permissions_data = [
                {'name': Permission.CREATE, 'description': 'Create permission'},
                {'name': Permission.READ, 'description': 'Read permission'},
                {'name': Permission.UPDATE, 'description': 'Update permission'},
                {'name': Permission.DELETE, 'description': 'Delete permission'},
            ]
            
            permissions = {}
            for perm_data in permissions_data:
                perm, created = Permission.objects.get_or_create(
                    name=perm_data['name'],
                    defaults={'description': perm_data['description']}
                )
                permissions[perm.name] = perm
                status = 'Created' if created else 'Already exists'
                self.stdout.write(f'  {status}: {perm.get_name_display()}')
            
            # Create Roles
            self.stdout.write('\nCreating roles...')
            roles_data = [
                {'name': Role.ADMIN, 'description': 'Admin role'},
                {'name': Role.EDITOR, 'description': 'Editor role'},
                {'name': Role.USER, 'description': 'User role'},
            ]
            
            roles = {}
            for role_data in roles_data:
                role, created = Role.objects.get_or_create(
                    name=role_data['name'],
                    defaults={'description': role_data['description']}
                )
                roles[role.name] = role
                status = 'Created' if created else 'Already exists'
                self.stdout.write(f'  {status}: {role.get_name_display()}')
            
            # Assign Permissions to Roles
            self.stdout.write('\nAssigning permissions to roles...')
            
            # Admin: All permissions
            admin_permissions = [Permission.CREATE, Permission.READ, Permission.UPDATE, Permission.DELETE]
            for perm_name in admin_permissions:
                RolePermission.objects.get_or_create(
                    role=roles[Role.ADMIN],
                    permission=permissions[perm_name]
                )
                self.stdout.write(f'  Admin: {permissions[perm_name].get_name_display()}')
            
            # Editor: Create, Read, Update (no Delete)
            editor_permissions = [Permission.CREATE, Permission.READ, Permission.UPDATE]
            for perm_name in editor_permissions:
                RolePermission.objects.get_or_create(
                    role=roles[Role.EDITOR],
                    permission=permissions[perm_name]
                )
                self.stdout.write(f'  Editor: {permissions[perm_name].get_name_display()}')
            
            # User: Read only
            user_permissions = [Permission.READ]
            for perm_name in user_permissions:
                RolePermission.objects.get_or_create(
                    role=roles[Role.USER],
                    permission=permissions[perm_name]
                )
                self.stdout.write(f'  User: {permissions[perm_name].get_name_display()}')
            
            # Create Admin User
            if not options['skip_admin']:
                self.stdout.write('\nCreating admin user...')
                
                # Check if admin already exists
                if User.objects.filter(is_superuser=True).exists():
                    self.stdout.write('  Admin user already exists')
                else:
                    # Get username
                    username = options.get('username')
                    if not username:
                        username = input('Enter admin username: ').strip()
                        if not username:
                            username = 'admin'
                    
                    # Check if username exists
                    if User.objects.filter(username=username).exists():
                        self.stdout.write(self.style.ERROR(f'  User {username} already exists'))
                    else:
                        # Get email
                        email = options.get('email')
                        if not email:
                            email = input('Enter admin email: ').strip()
                            if not email:
                                email = f'{username}@example.com'
                        
                        # Get password
                        while True:
                            password = getpass.getpass('Enter admin password: ')
                            if not password:
                                self.stdout.write(self.style.ERROR('  Password cannot be empty'))
                                continue
                            
                            password_confirm = getpass.getpass('Confirm admin password: ')
                            if password != password_confirm:
                                self.stdout.write(self.style.ERROR('  Passwords do not match'))
                                continue
                            
                            # Validate password
                            try:
                                validate_password(password)
                                break
                            except ValidationError as e:
                                self.stdout.write(self.style.ERROR(f'  Password validation failed:'))
                                for error in e.messages:
                                    self.stdout.write(self.style.ERROR(f'    - {error}'))
                        
                        # Create admin user
                        admin_user = User.objects.create_user(
                            username=username,
                            email=email,
                            password=password,
                            is_staff=True,
                            is_superuser=True,
                            is_default_admin=True,
                            force_password_change=False,
                            role=roles[Role.ADMIN]
                        )
                        
                        self.stdout.write(self.style.SUCCESS(f'  Created admin user: {username}'))
            
            # Summary
            self.stdout.write('\n' + '='*60)
            self.stdout.write(self.style.SUCCESS('RBAC System Initialized Successfully'))
            self.stdout.write('='*60)
            
            self.stdout.write('\nSummary:')
            self.stdout.write(f'  Permissions: {Permission.objects.count()}')
            self.stdout.write(f'  Roles: {Role.objects.count()}')
            self.stdout.write(f'  Role-Permission Mappings: {RolePermission.objects.count()}')
            self.stdout.write(f'  Users: {User.objects.count()}')
            
            self.stdout.write('\nNext Steps:')
            self.stdout.write('  1. Start server: python manage.py runserver')
            self.stdout.write('  2. Login with your admin credentials')
            self.stdout.write('  3. Create users via API')
            self.stdout.write('')
