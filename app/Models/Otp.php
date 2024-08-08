<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Otp extends Model
{
    use HasFactory;

    protected $table = 'otp';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['otp','key','extra_field','status'];
}
