<?php

namespace PodPoint\LaravelCognitoAuth;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient as AWSCognitoClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

class CognitoClient
{
    /**
     * Constant representing the user needs a new password.
     *
     * @var string
     */
    const NEW_PASSWORD_CHALLENGE = 'NEW_PASSWORD_REQUIRED';

    /**
     * Constant representing the force new password status.
     *
     * @var string
     */
    const FORCE_PASSWORD_STATUS = 'FORCE_CHANGE_PASSWORD';

    /**
     * Constant representing the password reset required exception.
     *
     * @var string
     */
    const RESET_REQUIRED = 'PasswordResetRequiredException';

    /**
     * Constant representing the user not found exception.
     *
     * @var string
     */
    const USER_NOT_FOUND = 'UserNotFoundException';

    /**
     * Constant representing the username exists exception.
     *
     * @var string
     */
    const USERNAME_EXISTS = 'UsernameExistsException';

    /**
     * Constant representing the invalid password exception.
     *
     * @var string
     */
    const INVALID_PASSWORD = 'InvalidPasswordException';

    /**
     * Constant representing the code mismatch exception.
     *
     * @var string
     */
    const CODE_MISMATCH = 'CodeMismatchException';

    /**
     * Constant representing the expired code exception.
     *
     * @var string
     */
    const EXPIRED_CODE = 'ExpiredCodeException';

    /**
     * AWS Cognito Client
     *
     * @var AWSCognitoClient
     */
    protected $client;

    /**
     * Cognito Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Cognito Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Cognitor Pool ID
     *
     * @var string
     */
    protected $poolId;

    /**
     * CognitoClient Constructor
     *
     * @param AWSCognitoClient $client
     * @param string           $clientId
     * @param string           $clientSecret
     * @param string           $poolId
     */
    public function __construct(AWSCognitoClient $client, $clientId, $clientSecret, $poolId)
    {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
    }

    /**
     * Check a users credentials.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     *
     * @param  string $email
     * @param  string $password
     * @return bool
     */
    public function authenticate($email, $password)
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->cognitoSecretHash($email),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::RESET_REQUIRED || $e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return false;
            }

            throw $e;
        }

        return $response;
    }

    /**
     * Registers a new user and sets their email as verified.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html
     *
     * @param  string $username
     * @param  string $password
     * @param  array $attributes
     * @return \Aws\Result
     */
    public function register($username, $password, array $attributes = [])
    {
        try {
            $response = $this->client->signUp([
                'ClientId' => $this->clientId,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($username),
                'UserAttributes' => $this->formatAttributes($attributes),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw $e;
        }

        return $response;
    }

    /**
     * Set a users attributes.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html
     *
     * @param string $username
     * @param array  $attributes
     * @return bool
     */
    public function setUserAttributes($username, array $attributes)
    {
        $this->client->AdminUpdateUserAttributes([
            'Username' => $username,
            'UserPoolId' => $this->poolId,
            'UserAttributes' => $this->formatAttributes($attributes),
        ]);

        return true;
    }

    /**
     * Send a password reset code to a user.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
     *
     * @param  string $username
     * @return string
     */
    public function sendResetLink($username)
    {
        try {
            $this->client->forgotPassword([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return Password::INVALID_USER;
            }

            throw $e;
        }

        return Password::RESET_LINK_SENT;
    }

    /**
     * Reset a users password based on reset code.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html
     *
     * @param  string $code
     * @param  string $username
     * @param  string $password
     * @return string
     */
    public function resetPassword($code, $username, $password)
    {
        try {
            $this->client->confirmForgotPassword([
                'ClientId' => $this->clientId,
                'ConfirmationCode' => $code,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND) {
                return Password::INVALID_USER;
            }

            if ($e->getAwsErrorCode() === self::INVALID_PASSWORD) {
                return Password::INVALID_PASSWORD;
            }

            if ($e->getAwsErrorCode() === self::CODE_MISMATCH || $e->getAwsErrorCode() === self::EXPIRED_CODE) {
                return Password::INVALID_TOKEN;
            }

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }

    /**
     * Register a user and send them an email to set their password.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
     *
     * @param  string $email
     * @param  array  $attributes
     * @return bool
     */
    public function inviteUser($username, array $attributes = [])
    {
        $attributes['email'] = $username;
        $attributes['email_verified'] = 'true';

        try {
            $this->client->AdminCreateUser([
                'UserPoolId' => $this->poolId,
                'TemporaryPassword' => Str::random(40),
                'DesiredDeliveryMediums' => [
                    'EMAIL'
                ],
                'Username' => $username,
                'UserAttributes' => $this->formatAttributes($attributes),
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USERNAME_EXISTS) {
                return false;
            }

            throw $e;
        }

        return true;
    }

    /**
     * Set a new password for a user that has been flagged as needing a password change.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html
     *
     * @param  string $username
     * @param  string $password
     * @param  string $session
     * @return bool
     */
    public function confirmPassword($username, $password, $session)
    {
        try {
            $this->client->AdminRespondToAuthChallenge([
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
                'Session'  => $session,
                'ChallengeResponses' => [
                    'NEW_PASSWORD' => $password,
                    'USERNAME' => $username,
                    'SECRET_HASH' => $this->cognitoSecretHash($username)
                ],
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED'
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::CODE_MISMATCH || $e->getAwsErrorCode() === self::EXPIRED_CODE) {
                return Password::INVALID_TOKEN;
            }

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }

    /**
     * Get user details.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html
     *
     * @param  string $username
     * @return mixed
     */
    public function getUser($username)
    {
        try {
            $user = $this->client->AdminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return $user;
    }

    /**
     * Confirms registration of a user
     * https://docs.aws.amazon.com/aws-sdk-php/v3/api/api-cognito-idp-2016-04-18.html#confirmsignup
     *
     * @param $username
     * @param $confirmationCode
     * @return bool
     * @throws CognitoIdentityProviderException
     */
    public function confirmSignUp($code, $username)
    {
        try {
            $this->client->confirmSignUp([
                'ClientId' => $this->clientId,
                'ConfirmationCode' => $code,
                'Username' => $username,
                'SecretHash' => $this->cognitoSecretHash($username),
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === self::USER_NOT_FOUND || $e->getAwsErrorCode() === self::CODE_MISMATCH || $e->getAwsErrorCode() === self::EXPIRED_CODE) {
                return false;
            }

            throw $e;
        }

        return true;
    }

    /**
     * Gets the user attributes and metadata for a user.
     * https://docs.aws.amazon.com/aws-sdk-php/v3/api/api-cognito-idp-2016-04-18.html#getuser
     *
     * @param $accessToken
     * @return \Aws\Result
     * @throws CognitoIdentityProviderException
     */
    public function getUserByAccessToken($accessToken)
    {
        try {
            $user = $this->client->getUser([
                'AccessToken' => $accessToken,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw $e;
        }

        return $user;
    }

    /**
     * Get AWS Cognito Client
     *
     * @return AWSCognitoClient
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Registers a new user with phone number as a username
     *
     * @param $phoneNumber
     * @param $password
     * @param array $attributes
     * @return \Aws\Result|bool
     */
    public function signUpWithPhoneNumber($phoneNumber, $password, array $attributes = [])
    {
        $attributes['phone_number'] = $phoneNumber;

        return $this->register($phoneNumber, $password, $attributes);
    }

    /**
     * Resends the confirmation (for confirmation of registration) to a specific user in the user pool.
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ResendConfirmationCode.html
     *
     * @param string $username
     */
    public function resendConfirmationCode($username)
    {
        try {
            $response = $this->client->resendConfirmationCode([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw $e;
        }

        return $response;
    }

    /**
     * Create Cognito secret hash
     *
     * @param  string $username
     * @return string
     */
    protected function cognitoSecretHash($username)
    {
        return $this->hash($username . $this->clientId);
    }

    /**
     * Create HMAC from string
     *
     * @param  string $message
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }

    /**
     * Format attributes in Name/Value array
     *
     * @param  array $attributes
     * @return array
     */
    protected function formatAttributes(array $attributes)
    {
        $userAttributes = [];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => $key,
                'Value' => $value,
            ];
        }

        return $userAttributes;
    }
}
