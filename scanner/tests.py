from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User


class AuthenticationFlowTests(TestCase):
    def test_user_signup_and_login_redirect(self):
        signup_url = reverse('signup')
        login_url = reverse('login')

        response = self.client.get(signup_url)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(signup_url, {
            'username': 'normaluser',
            'password1': 'SuperSecure123!',
            'password2': 'SuperSecure123!',
        })
        self.assertRedirects(response, reverse('index'))

        self.client.logout()
        login = self.client.post(login_url, {'username': 'normaluser', 'password': 'SuperSecure123!'}, follow=True)
        self.assertContains(login, 'NETGUARD')

    def test_admin_login_redirects_to_admin(self):
        admin = User.objects.create_superuser('adminuser', 'admin@example.com', 'AdminSecure123!')
        login_url = reverse('login')

        resp = self.client.post(login_url, {'username': 'adminuser', 'password': 'AdminSecure123!'}, follow=False)
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.url.startswith('/admin/'))

