<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class FcmTokens extends Model
{
    use HasFactory;

    protected $table = 'fcm_token';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['device_id','fcm_token','extra_field','status'];

}
