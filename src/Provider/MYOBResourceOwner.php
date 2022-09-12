<?php

namespace GlobalVisionMedia\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;




class MYOBResourceOwner implements ResourceOwnerInterface {

  use ArrayAccessorTrait;


  /**
   * Creates new resource owner.
   *
   * @param array  $response
   */
  public function __construct(array $response = array()) {
    $this->response = json_decode($response,true);
  }

  /**
   * Returns the identifier of the authorized resource owner.
   *
   * @return mixed
   */
  public function getId() {
    return $this->getValueByKey($this->response, 'username');
  }

  /**
   * Return all of the owner details available as an array.
   *
   * @return array
   */
  public function toArray() {
    return $this->response;
  }
}
