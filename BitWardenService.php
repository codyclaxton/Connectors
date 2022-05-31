<?php

namespace App\Services\Integrations\Core;



class BitWardenService extends BaseIntegrationService implements ProvisionableServiceInterface
{

    use Provisionable;

    protected static string $apiUrl = "https://api.bitwarden.com";
    protected static string $tokenUrl = "https://identity.bitwarden.com/connect/token";
    protected static string $grantType = "client_credentials";
    protected static string $scope = "api.organization";

    public static function getAccessToken($identifier)
    {
        $app = static::getApplication($identifier);
        $token = $app->access_token;

        // Check if tokens exist
        if (empty($token) || empty($token['access_token'])) {
            return static::refreshAccessToken($identifier);
        }

        if(!isset($token['expiration']) || $token['expiration'] < time()) {
            //the token is expired and we need to get a new one
            return static::refreshAccessToken($identifier);
        }

        // Token is still valid, just return it
        return $token['access_token'];
    }

    public static function refreshAccessToken($identifier)
    {
        $app = static::getApplication($identifier);
        $token_url = static::$tokenUrl;

        $auth_params = [
            'grant_type' => static::$grantType,
            'scope' => static::$scope,
            'client_id' => $app->getCredential('client_id'),
            'client_secret' => $app->getCredential('client_secret')
        ];

        $auth_headers = [
            'User-Agent' => 'claritysecurity.io',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => '*/*',
        ];
        $client = new Client();
        //1
        $response = $client->post($token_url, ['headers' => $auth_headers, 'form_params' => $auth_params]);
        $response = json_decode($response->getBody(), true);

        $access_token = $response['access_token'];
        $expiration = time() + $response['expires_in'];

        $token = [
            'access_token' => $access_token,
            'expiration' => $expiration
        ];

        $app->access_token = $token;
        $app->save();

        return $access_token;
    }

    public static function buildHttpHeaders($identifier, $token)
    {
        return Http::withHeaders([
            'accept' => '*/*',
            'Authorization' => "Bearer " . $token,
            'User-Agent' => 'Clarity',
            'Content-Type' => "application/json-patch+json"
        ]);
    }

    public static function importEntitlements($identifier)
    {
        $app = static::getApplication($identifier);

        // Group entitlements
        $groups = static::callApiEndpoint($identifier, '/public/groups', 'GET');
        if ($groups !== false && isset($groups['data'])) {
            foreach ($groups['data'] as $group) {
                $cl_entitlement = Entitlement::where('application_id', $app->instance_id)
                    ->where('name', $group['name'])
                    ->where('is_head_revision', 1)
                    ->first();
                if (!$cl_entitlement) {
                    $cl_entitlement = new Entitlement();
                    $cl_entitlement->application_id = $app->instance_id;
                    $cl_entitlement->name = $group['name'];
                    $cl_entitlement->resources = ["type" => "group"];
                    $cl_entitlement->extra_params = ['id' => $group['id']];
                    $cl_entitlement->save();
                } else {
                    $cl_entitlement->markAsFresh();
                }
            }
        } else {
            return false;
        }

        // Type entitlements
        // Note: ignoring Custom type (4) as it has many customizable settings that we can't change
        // and each user's custom properties are different.
        $user_types = [
            0 => 'Owner',
            1 => 'Admin',
            2 => 'User',
            3 => 'Manager'
            //4 => 'Custom'
        ];

        foreach ($user_types as $key => $value) {
            $cl_entitlement = Entitlement::where('application_id', $app->instance_id)
                ->where('name', $value)
                ->where('is_head_revision', 1)
                ->first();
            //Check if the user type has  been added before
            if (!$cl_entitlement) {
                $cl_entitlement = new Entitlement();
                $cl_entitlement->application_id = $app->instance_id;
                $cl_entitlement->name = $value;
                $cl_entitlement->resources = ["type" => "type"];
                $cl_entitlement->extra_params = ["type" => $key];
                $cl_entitlement->save();
            } else {
                $cl_entitlement->markAsFresh();
            }
        }
    }

    public static function testApi($identifier)
    {
        $users = static::callApiEndpoint($identifier,  "/public/members", "GET", false);
        return ($users !== false);
    }

    public static function importUsers($identifier, $creator)
    {
        $users = static::callApiEndpoint($identifier,  "/public/members", "GET", false);
        if ($users !== false && !empty($users['data'])) {
            static::importUserQueueBatchJob($identifier, $users['data'], $creator);
        } else {
            return false;
        }
    }

    public static function findIdentityInClarityFromUser($identifier, $user, $useFallbacks = true)
    {
        $identity = Identity::findByServiceIdentifier($identifier, $user['id']);

        if (!$identity && isset($user['email']) && $useFallbacks) {
            //try to find them using email address
            $identity = Identity::findByServiceIdentifier($identifier, $user['email'], true);
        }

        return $identity;
    }

    public static function importUser($identifier, $user, $creator)
    {
        // import users who are active (2) and who are invited (0)
        if ($user['status'] == 2 || $user['status'] == 0) {

            $app = static::getApplication($identifier);
            $identity = static::findIdentityInClarityFromUser($identifier, $user);

            if ($identity) {
                static::addClarityEntitlement($identity, static::getBaseEntitlement($identifier), '', 'role');
                $identity->updateServiceIdentifier($user['id'], $identifier);

                // Create an identity attribute for the accessAll value as it's used when you're changing roles in the
                // add & remove entitlements to identity methods. The API returns a bool, so we convert it to a string
                // in the DB. When we access the variable and use it, we'll convert it back to a bool.
                $identity->addOrUpdateIdentityAttributeValue('accessAll', $user['accessAll']? "true":"false", $identifier, 0, false);

                // Add role entitlement to the identity.
                // Note: ignoring Custom role (4) as it has many customizable settings that we can't change
                // and each user's custom properites are different.
                $cl_entitlement = Entitlement::where('application_id', $app->instance_id)
                    ->where('extra_params->type', $user['type'])
                    ->where('is_head_revision', 1)
                    ->where('resources->type', 'type')
                    ->first();
                if ($cl_entitlement) {
                    static::addClarityEntitlement($identity, $cl_entitlement, '', 'role');
                }

                // User object does not contain group information. Retrieve a list of groups that the user belongs to
                // and iterate over it
                $groups = static::callApiEndpoint($identifier, '/public/members/' . $user['id'] . '/group-ids', 'GET');
                if ($groups !== false && !empty($groups)) {
                    foreach ($groups as $group) {
                        $cl_entitlement = Entitlement::where('application_id', $app->instance_id)
                            ->where('extra_params->id', $group)
                            ->where('is_head_revision', 1)
                            ->where('resources->type', 'group')
                            ->first();
                        if ($cl_entitlement) {
                            static::addClarityEntitlement($identity, $cl_entitlement, '', 'role');
                        }
                    }
                }

            } else {
                $serviceData = [
                    "user" => $user
                ];
                static::handleImportConflict($identifier, $user['id'], $serviceData, $creator, $user['email']);
            }
        }
    }

    public static function getUser($identifier, Identity $identity)
    {
        $serviceIdentifier = $identity->getServiceIdentifier($identifier, false);
        if($serviceIdentifier !== false) {
            $user = static::callApiEndpoint($identifier, "/public/members/$serviceIdentifier", "GET", false);
            if($user !== false && !empty($user)) {
                $identity->updateServiceIdentifier($user['id'], $identifier);
                return $user;
            }
        }

        return false;
    }

    public static function addServiceEntitlementToIdentity($identifier, Entitlement $entitlement, Identity $identity, $expiration, $grantType)
    {
        if (static::checkOrAddIdentity($identifier, $identity)) {
            static::addClarityEntitlement($identity, static::getBaseEntitlement($identifier), '', $grantType);
            $id = $identity->getServiceIdentifier($identifier, false);

            if ($id) {
                switch ($entitlement->resources['type']) {
                    case "group":
                        $params = [
                            "groupIds" => [
                                $entitlement['extra_params']['id']
                            ]
                        ];
                        $result = static::callApiEndpoint($identifier, "/public/members/" . $id . "/group-ids", 'PUT', false, $params);
                        break;
                    case "type":
                        // Get the access all value from the identity attributes and convert the string to a bool
                        $accessAll = $identity->getIdentityAttributeValueByName('accessAll', $identifier);
                        $bool_accessAll = filter_var($accessAll, FILTER_VALIDATE_BOOLEAN);

                        $params = [
                            "type" => $entitlement['extra_params']['type'],
                            "accessAll" => $bool_accessAll
                        ];
                        $result = static::callApiEndpoint($identifier, "/public/members/" . $id, 'PUT', false, $params);
                        break;
                    default:
                        HelperService::log('Bad data. Entitlement has unexpected resource type. Entitlement ID: ' . $entitlement->id, 'warning');
                        return false;
                }

                if ($result !== false) {
                    static::addClarityEntitlement($identity, $entitlement, $expiration, $grantType);
                    return true;
                } else {
                    if (!App::environment('testing')) {
                        HelperService::addToast("An error occurred when adding an entitlement to identity: $identity->fullname",
                            "error");
                    }
                    return false;
                }
            } else {
                HelperService::addToast("Could not find a service identifier for the employee, even though they do have an account.",
                    "warning");
                return false;
            }
        } else {
            return false;
        }

    }

    public static function removeServiceEntitlementFromIdentity($identifier, IdentityEntitlement $identityEntitlement)
    {
        $id = $identityEntitlement->identity->getServiceIdentifier($identifier, false);
        $entitlement = $identityEntitlement->entitlement;

        if ($id) {
            $result = false;
            switch ($entitlement->resources['type']) {
                case "group":
                    // Retrieve a list of users in a group by IDs
                    $get_group_members = static::callApiEndpoint($identifier, '/public/groups/' . $entitlement->extra_params['id'] . '/member-ids', 'GET');

                    // Search for the user ID in the array. If the value is found, unset it from the array.
                    $key = array_search($id, $get_group_members);
                    if($key !== false) {
                        unset($get_group_members[$key]);
                    }

                    // Build out request body with updated list of all members in a group and send it to the api
                    $params = [
                        "memberIds" => $get_group_members
                    ];
                    $result = static::callApiEndpoint($identifier, '/public/members/' . $id . '/group-ids', 'PUT', false, $params);
                    break;
                case "type":
                    // Get the access all value from the identity attributes and convert the string to a bool
                    $accessAll = $identityEntitlement->identity->getIdentityAttributeValueByName('accessAll', $identifier);
                    $bool_accessAll = filter_var($accessAll, FILTER_VALIDATE_BOOLEAN);

                    $params = [
                        "type" => $entitlement->extra_params['type'],
                        "accessAll" => $bool_accessAll
                    ];
                    $result = static::callApiEndpoint($identifier, '/public/members/' . $id, 'PUT', false, $params);
                    break;
                default:
                    HelperService::log('Bad data. Entitlement has unexpected resource type. Entitlement ID: ' . $entitlement->id, 'warning');
            }

            return $result !== false;

        } else {
            return false;
        }

    }

    public static function deactivateUser($identifier, $serviceIdentifier)
    {
        // No deactivate user endpoint
    }

    public static function deleteUser($identifier, $serviceIdentifier)
    {
        // Permanently deletes a member from the organization. This cannot be undone. The user account will still remain.
        // The user is only removed from the organization.
        return static::callApiEndpoint($identifier, "/public/members/$serviceIdentifier", 'DELETE');
    }

    public static function createNewUser($identifier, Identity $identity)
    {
        // Creating a new user requires the "type" value to be set as a default entitlement
        // Grab the default type entitlement or else, throw an alert.
        $defaultEntitlement = static::getDefaultEntitlement($identifier);

        if($defaultEntitlement !== false && $defaultEntitlement->resources['type'] == "type") {
            $params = [
                "externalId" => "",
                "type" => $defaultEntitlement->extra_params['type'],
                "accessAll" => false,
                "resetPasswordEnrolled" => false,
                "collections" => [],
                "email" => $identity->email
            ];

            $user = static::callApiEndpoint($identifier, "/public/members", 'POST', false, $params);

            if($user !== false) {
                $identity->updateServiceIdentifier($user['id'], $identifier);
                return $user;
            } else {
                return false;
            }
        } else {
            HelperService::addAlert("The default entitlement for new users for $identifier is not of the proper type. Please select a valid 'type'");
            return false;
        }

    }
}
