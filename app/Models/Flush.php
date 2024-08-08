<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Flush extends Model
{
    use HasFactory;

    protected $table = 'flush';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['key','value','extra_field','status'];

}
