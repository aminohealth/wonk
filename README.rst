The Policy Wonk
===============

Wonk is a tool for combining a set of AWS policy files into smaller compiled `policy sets`_.

Table of Contents
-----------------

.. contents:: Contents:

Rationale
=========

Wonk can help you in several situations.

Policies are limited resources
------------------------------

You want to give the people in your organization the AWS permissions needed to do their job. Amazon has helpfully created several hundred policies like ``AmazonRDSReadOnlyAccess`` and ``AmazonS3FullAccess`` that you can assign to users, groups, or roles. This is super convenient... up until it's not.

AWS has `IAM quotas`_ like:

* Policies may not be more than 6,144 characters long.
* You can't attach more than 10 groups or roles to a user.
* You can't attach more than 10 policies to a single group, role, or user.
* If you're logging into AWS with SSO, each user like gets exactly 1 role assigned to them.

What if your backend engineers log in with Okta and they need **11** policies to do their job?

Wonk to the rescue! You can combine them into one big policy with a command line like:

::

    $ wonk combine -p MyPolicy AWSPolicy1.json AWSPolicy2.json

which reads the contents of ``AWSPolicy1.json`` and ``AWSPolicy2.json`` and merges them into a ``MyPolicy.json`` file.

Your roles share a lot of common permissions
--------------------------------------------

Perhaps you have one role for backend engineers, and another role for backend engineers who are on call this week and need some additional permissions. You really don't want to maintain two policies that are nearly identical, though.

In this case, you could put all of the standard permissions in one policy, all of the additional on-call permissions in another, then combine them:

::

    $ wonk combine -p BackendOnCall Backend.json OnCall.json

Things got really complicated when you weren't looking
------------------------------------------------------

Beyond just combining a file or 2 as needed, you want some help managing multiple roles with lots of policies. Say you're setting up policies for both frontend and backend engineers and each of them have special on-call roles that share some extra debugging permissions. Each role uses a combination of some AWS-managed policies with some that you've written yourself.

Wonk loves you and wants you to be happy.

First, it assumes a directory layout like this:

::

    ├── wonk.yaml
    ├── managed
    │   ├── AWSPolicy1.json
    │   └── AWSPolicy2.json
    ├── local
    │   ├── BackendECSReadOnly.json
    │   ├── FrontendCloudWatchReadOnly.json
    │   └── OnCall.json
    └── combined
        ├── Backend_1.json
        ├── Frontend_1.json
        ├── BackendOnCall_1.json
        └── FrontendOnCall_1.json

where the ``managed`` directory is full of policy files that you've downloaded from AWS (maybe using the ``wonk fetch`` command), the ``local`` directory has policies you've written yourself, and ``combined`` has the output files that Wonk creates for you.

You **could** write a bunch of ``wonk combine`` command lines, maybe in a shell script or a Makefile. Alternatively, you could write a ``wonk.yaml`` file like this:

::

    policy_sets:
      Backend:
        managed:
          - AWSPolicy1
          - arn:path:to:your:policy/AWSPolicy2
        local:
          - BackendECSReadOnly

      BackendOnCall:
        inherits:
          - Backend
        local:
          - OnCall

      Frontend:
        managed:
          - AWSPolicy3
        local:
          - FrontendCloudWatchReadOnly

      FrontendOnCall:
        inherits:
          - Frontend
        local:
          - OnCall

and then tell Wonk to build them all for you:

::

    $ wonk build --all

which fetches any missing managed policies, then creates a set of combined policies named after their YAML configurations.

A managed policy ``Foo`` is fetched by the ARN ``arn:aws:iam::aws:policy/Foo``. However, some Amazon policies don't follow that convention. In that case, you can give an ARN instead of a policy name and that ARN will be fetched instead (and the policy's name will be derived from the ARN). You could also do that if you want to fetch your own policy from Amazon instead of maintaining it locally.

Installation
============

Today: clone this repo and run ``poetry install``.

Soon: ``pip install wonk``.

Usage
=====

Fetching policies
-----------------

Use ``wonk fetch`` to retrieve a policy from AWS by name or by ARN and write it to stdout. Each of these commands emit the same output:

::

    $ wonk fetch --arn "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
    $ wonk fetch --name AWSLambdaFullAccess
    $ wonk fetch --profile my_aws_profile_name --name AWSLambdaFullAccess

Combining policies
------------------

Use ``wonk combine`` to combine multiple policies into a policy set:

::

    $ wonk combine -p Foo policy1.json policy2.json

Building configured policy statements
-------------------------------------

The ``wonk build`` command interprets a ``wonk.yaml`` file as described in the example above and builds the requested policy set(s).

To build one named policy set:

::

    $ wonk build --policy-set BackendOnCall

To build all defined policy sets:

::

    $ wonk build --all

The details
===========

Sounds simple, right? Well, not quite. Remember, IAM quotas limit managed policies to 6,144 characters. You can put a few more characters on an inline policy directly on a role, but that's not best practice and you don't really want to go down that path. Instead, Wonk uses a few tricks to try to make policies fit inside their size limit:

* It strips all ``Sid`` keys from statements, per Amazon's recommendations.
* It discard duplicate actions.
* It removes all "shadowed" actions. For instance, if a statement has actions ``Foo:SomeAction`` and ``Foo:*``, it discards ``Foo:SomeAction`` because ``Foo:*`` already has it covered. Similarly, ``Foo:Get*`` will shadow ``Foo:GetSomething``, so ``Foo:GetSomething`` will be removed.
* Wonk tries to make the generated policies as human-readable as possible, but will format them very tersely if necessary. You can always use jq_ to reformat its outputs for viewing.

Note: actions are always grouped by similar principals, resources, conditions, etc. If two statements have different conditions, say, they are processed separately.

Breaking up is hard to do
-------------------------

Wonk does whatever it can to make a policy fit within that magic 6,144 character limit, but somethings that just can't be done. If you try to combine 30 different non-overlapping policies, there's a decent chance that the end result simply can't be shrunk enough. A careful reader might have noticed that all of the command examples specify an output "base" instead of a specific filename, and an output ``Foo`` ends up creating a file named ``Foo.json``. This is because in the case that Wonk can't pack everything into a separate file, it creates a **set** of as few output policies as possible to include all of the actions. The general process is this:

* Try to make everything fit.
* If there are any statements with so many actions that they can't be shrunk into the size limit, split them up into equal-size chunks that do fit.
* Now we have the case of fitting **M** statements into **N** policies, of which there can't be more than 10 because of the AWS limits. That looks a lot like the `knapsack problem`_, and indeed it is. Wonk uses Google's `SCIP constraint solver`_ to pack all of the statements into as few policies as possible.
* If **none** of this is sufficient, Wonk raises an exception and quits.

Policy sets
-----------

The end result of many Wonk operations is a collection of files, a **policy set**, named ``<base>_1.json`` through ``<base>_N.json`` where N <= 10. This is different from most utilities which operate on individual files, but Wonk can't know how many files it will be creating in advance.

Why 10? Because AWS usually won't allow you to attach more than 10 policies to a user, group, or role. Since policy sets work together like one giant policy and can't be split up, Wonk won't create a policy set that can't actually be attached to anything. If you're bumping up against this limit, consider creating 2 policy sets and applying them to 2 distinct but groups (like ``Backend_1`` and ``Backend_2``), then putting each relevant user into both groups. Alternatively, if your policies cover 99 actions like ``Service:OnePermission`` and ``Service:Another`` on a service that only has 100 possible actions, and you've done your due diligence and don't mind giving your users access to that 100th action, consider adding a ``Service:*`` action to a local policy. That will replace all those individual actions with the single wildcard. Likewise, if you mean to give your users access to all of the various ``Service:GetThis`` and ``Service:GetThat`` actions, you can cover them all at once with ``Service:Get*``. This also has the nice side effect of documenting that you actually intend to allow access to all of the ``Get*`` actions.

Terraforming combined policies
==============================

Reasonably recent modern versions of Terraform support ``fileset`` and ``for_each`` syntax. You can define a single policy resource that exactly expands out to a whole set of policies, then attach them all at once to a group or role:

::

    resource "aws_iam_policy" "Frontend" {
      for_each    = fileset(path.module, "combined/Frontend_*.json")
      name        = split(".", basename(each.value))[0]
      description = "Frontend users need to do stuff"
      policy      = file(each.value)
    }

    resource "aws_iam_group_policy_attachment" "Frontenders__Frontend" {
      for_each   = aws_iam_policy.Frontend
      group      = data.aws_iam_group.frontenders.group_name
      policy_arn = each.value.arn
    }

Limitations
===========

As of this writing, Wonk is usable but not finished. It's missing a few nice features:

* Wonk doesn't consider action shadowing when one statement has restrictions but another doesn't. For example, given two statement blocks:

::

    {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "Foo:Something",
                "Resource": "arn:aws:service::my_resource"
            },
            {
                "Effect": "Allow",
                "Action": "Foo:Something"
            }
        ]
    }

the second statement is broader than the first, so the first could be safely removed. Right now it isn't.

Copyright
=========

The Policy Wonk is copyright 2021 Amino, Inc. and distributed under the terms of the Apache-2.0 License.

.. _IAM quotas: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
.. _jq: https://stedolan.github.io/jq/
.. _knapsack problem: https://en.wikipedia.org/wiki/Knapsack_problem
.. _SCIP constraint solver: https://developers.google.com/optimization/mip/integer_opt
