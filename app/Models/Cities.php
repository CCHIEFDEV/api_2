<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Cities extends Model
{
    use HasFactory;

    protected $table = 'cities';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['name','cover','lat','lng','extra_field','status'];

}
